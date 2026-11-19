"""BGE-M3 混合检索与按需加载入口。"""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable

import orjson

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RAGConfig:
    enable_rag: bool
    enable_r155: bool
    r155_annex5_path: str
    vector_store_dir: str
    verify_model_hashes: bool
    reranker_enabled: bool
    reranker_model_path: str
    reranker_candidates: int
    reranker_batch_size: int
    rrf_k: int
    bge_m3_path: str


class LazyRAGKnowledgeBase:
    """首次使用时才选择 GPU、加载记录并创建知识库实例。"""

    def __init__(self, factory: Callable[[], BGEM3RAGKnowledgeBase]):
        self._factory = factory
        self._instance: BGEM3RAGKnowledgeBase | None = None
        self._lock = Lock()

    def _get(self) -> BGEM3RAGKnowledgeBase:
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    logger.info("首次 RAG 请求：延迟初始化知识库")
                    self._instance = self._factory()
        return self._instance

    def __getattr__(self, name: str) -> Any:
        return getattr(self._get(), name)


SNIPPET_MAX_LENS: dict[str, int] = {
    "damage_scenario": 500, "impact_rating": 500,
    "threat_scenario": 1200, "attack_path": 1200, "attack_feasibility": 600,
}


class BGEM3RAGKnowledgeBase:
    """BGE-M3 (Dense+Sparse) 混合召回 + RRF + Cross-Encoder 重排的 RAG.

    Dense：BGE-M3 均值池化 + L2 归一化 → 余弦相似度
    Sparse：BGE-M3 sparse_linear 逐 token 权重 → 内积
    融合：RRF (Reciprocal Rank Fusion) → top-50
    重排：Cross-Encoder (bge-reranker-v2-m3) → top-5
    """

    def __init__(
        self,
        rag_dirs: dict[str, str],
        *,
        config: RAGConfig,
        model_hash_verifier: Callable[[str, str], bool] | None = None,
    ):
        self.rag_dirs = rag_dirs
        self.config = config
        self.reranker_enabled = config.reranker_enabled
        self.reranker_model_path = config.reranker_model_path
        self.reranker_candidates = config.reranker_candidates
        self.reranker_batch_size = config.reranker_batch_size
        self.rrf_k = config.rrf_k
        self.bge_m3_path = config.bge_m3_path
        self._verify_model_hashes = model_hash_verifier or (lambda _manifest, _model: True)

        self._lock = Lock()
        self._model_lock = Lock()
        self._cpu_lock = Lock()
        self._reranker_lock = Lock()

        # RAG 模型选择空闲最多的 GPU
        self._rag_device = self._pick_best_gpu()

        self._loaded = False
        self._reranker = None
        self.records: list[dict] = []

        # BGE-M3 model (lazy)
        self._model = None
        self._tokenizer = None
        self._sparse_linear_weight = None
        self._sparse_linear_bias = None
        self._device = None

        # BGE-M3 CPU fallback (for R155 matching)
        self._cpu_model = None
        self._cpu_tokenizer = None
        self._cpu_sparse_linear_weight = None
        self._cpu_sparse_linear_bias = None

        # Encoded vectors
        self.dense_embeddings = None
        self.sparse_weights: list[dict[int, float]] = []
        self._sparse_inverted: dict[int, list[tuple[int, float]]] = {}

        # R155 lazy-loaded attributes (initialized to avoid AttributeError when RAG disabled)
        self._r155_ids: list[str] = []
        self._r155_texts: list[str] = []
        self._r155_dense = None

    # ── 文件解析 ────────────────────────────────────

    @staticmethod
    def _safe_read_text(path: str) -> str:
        for enc in ("utf-8", "utf-8-sig", "gbk", "gb18030"):
            try:
                with open(path, "r", encoding=enc) as f:
                    return f.read()
            except Exception:
                continue
        return ""

    @staticmethod
    def _load_json_text(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = orjson.loads(f.read())
            if isinstance(obj, (dict, list)):
                return orjson.dumps(obj).decode("utf-8")
            return str(obj)
        except Exception:
            return BGEM3RAGKnowledgeBase._safe_read_text(path)

    @staticmethod
    def _parse_jsonl(path: str) -> list[dict]:
        chunks: list[dict] = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = orjson.loads(line)
                    except Exception:
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                    text = rec.get("text", "")
                    if not text or len(text.strip()) < 20:
                        continue
                    chunks.append({
                        "text": text.strip(),
                        "library_name": rec.get("library_name", ""),
                        "source_name": rec.get("source_name", ""),
                        "source_type": rec.get("source_type", ""),
                        "tara_phase": rec.get("tara_phase", []),
                        "knowledge_role": rec.get("knowledge_role", ""),
                    })
        except Exception as e:
            logger.warning("JSONL 解析失败 %s: %s", path, e)
        return chunks

    @staticmethod
    def _parse_pdf(path: str) -> str:
        try:
            import fitz
        except ImportError:
            logger.warning("pymupdf 未安装，跳过 PDF: %s", path)
            return ""
        try:
            doc = fitz.open(path)
            pages = [page.get_text() for page in doc if page.get_text()]
            doc.close()
            return "\n\n".join(pages)
        except Exception as e:
            logger.warning("PDF 解析失败 %s: %s", path, e)
            return ""

    @staticmethod
    def _parse_excel(path: str) -> str:
        try:
            import openpyxl
        except ImportError:
            logger.warning("openpyxl 未安装，跳过 Excel: %s", path)
            return ""
        try:
            wb = openpyxl.load_workbook(path, read_only=True)
            lines = []
            for ws in wb.worksheets:
                for row in ws.iter_rows(values_only=True):
                    line = " | ".join(str(c) for c in row if c is not None)
                    if line.strip():
                        lines.append(line)
            wb.close()
            return "\n".join(lines)
        except Exception as e:
            logger.warning("Excel 解析失败 %s: %s", path, e)
            return ""

    def _read_file(self, path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".pdf":
            return self._parse_pdf(path)
        elif ext == ".xlsx":
            return self._parse_excel(path)
        elif ext in {".txt", ".md"}:
            return self._safe_read_text(path)
        elif ext == ".json":
            return self._load_json_text(path)
        return ""

    # ── 切块（仅用于非 JSONL 源文件）────────────────

    @staticmethod
    def _chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
        if not text:
            return []
        if len(text) < chunk_size:
            return [text.strip()]
        paragraphs = re.split(r"\n\s*\n", text)
        paragraphs = [p.strip() for p in paragraphs if p.strip()]
        chunks: list[str] = []
        buffer = ""
        for para in paragraphs:
            if len(para) > chunk_size:
                if buffer:
                    chunks.append(buffer)
                    buffer = ""
                start = 0
                while start < len(para):
                    end = min(start + chunk_size, len(para))
                    chunks.append(para[start:end])
                    start = end - overlap if end < len(para) else len(para)
                continue
            if not buffer:
                buffer = para
            elif len(buffer) + len(para) + 2 <= chunk_size:
                buffer += "\n\n" + para
            else:
                chunks.append(buffer)
                buffer = para
        if buffer:
            if len(buffer) < 50 and chunks:
                chunks[-1] += "\n\n" + buffer
            else:
                chunks.append(buffer)
        return chunks

    # ── GPU 选择 ────────────────────────────────────

    @staticmethod
    def _pick_best_gpu() -> str:
        """选择空闲显存最多的 GPU 加载 RAG 模型（BGE-M3 / Cross-encoder）。"""
        import torch
        if not torch.cuda.is_available():
            return "cpu"
        best = 0
        best_free = 0
        total_mem = 0
        for i in range(torch.cuda.device_count()):
            free, total = torch.cuda.mem_get_info(i)
            if free > best_free:
                best_free = free
                best = i
                total_mem = total
        logger.info(
            "RAG 模型选 GPU %d（空闲 %.1fGB / %dGB）",
            best, best_free / (1024 ** 3), total_mem / (1024 ** 3),
        )
        return f"cuda:{best}"

    # ── 模型加载 ────────────────────────────────────

    def _ensure_model(self):
        if self._model is not None:
            return
        with self._model_lock:
            if self._model is not None:
                return
            import torch
            from transformers import AutoModel, AutoTokenizer

            if self.config.verify_model_hashes:
                if not self._verify_model_hashes(
                    os.path.join(self.bge_m3_path, "MANIFEST.sha256"),
                    self.bge_m3_path,
                ):
                    raise RuntimeError("BGE-M3 模型完整性校验失败")

            device_name = self._rag_device if self._rag_device.startswith("cuda") else "cpu"
            torch_dtype = torch.float16 if "cuda" in device_name else torch.float32
            logger.info("加载 BGE-M3 到 %s ...", device_name)
            self._tokenizer = AutoTokenizer.from_pretrained(self.bge_m3_path)
            self._model = AutoModel.from_pretrained(
                self.bge_m3_path, torch_dtype=torch_dtype,
            ).to(device_name).eval()
            sl = torch.load(
                os.path.join(self.bge_m3_path, "sparse_linear.pt"),
                map_location=device_name,
                weights_only=True,
            )
            self._sparse_linear_weight = sl["weight"].to(dtype=torch_dtype, device=device_name)
            self._sparse_linear_bias = sl["bias"].to(dtype=torch_dtype, device=device_name)
            self._device = device_name
            logger.info("BGE-M3 加载完成 (hidden_size=%d)", self._model.config.hidden_size)

    # ── 密集编码 ────────────────────────────────────

    def _encode_dense(self, texts: list[str], batch_size: int = 64):
        import numpy as np
        import torch
        all_embs = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            inputs = self._tokenizer(
                batch, padding=True, truncation=True, max_length=512, return_tensors="pt",
            ).to(self._device)
            with torch.no_grad():
                outputs = self._model(**inputs)
                last_hidden = outputs.last_hidden_state
                mask = inputs["attention_mask"].unsqueeze(-1).float()
                pooled = (last_hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
                pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
            all_embs.append(pooled.cpu().numpy())
        return np.concatenate(all_embs, axis=0)

    # ── CPU 编码 ───────────────────────────────────────

    def _ensure_model_cpu(self):
        if self._cpu_model is not None:
            return
        with self._cpu_lock:
            if self._cpu_model is not None:
                return
            import torch
            from transformers import AutoModel, AutoTokenizer

            if self.config.verify_model_hashes:
                if not self._verify_model_hashes(
                    os.path.join(self.bge_m3_path, "MANIFEST.sha256"),
                    self.bge_m3_path,
                ):
                    raise RuntimeError("BGE-M3 CPU 模型完整性校验失败")

            logger.info("加载 BGE-M3 到 CPU (fp32) ...")
            self._cpu_tokenizer = AutoTokenizer.from_pretrained(self.bge_m3_path)
            model = AutoModel.from_pretrained(self.bge_m3_path, torch_dtype=torch.float32)
            self._cpu_model = model.float().to("cpu").eval()
            sl = torch.load(
                os.path.join(self.bge_m3_path, "sparse_linear.pt"),
                map_location="cpu",
                weights_only=True,
            )
            self._cpu_sparse_linear_weight = sl["weight"].float()
            self._cpu_sparse_linear_bias = sl["bias"].float()
            logger.info("BGE-M3 CPU 加载完成 (hidden_size=%d)", self._cpu_model.config.hidden_size)

    def _encode_dense_cpu(self, texts: list[str], batch_size: int = 8):
        import numpy as np
        import torch
        self._ensure_model_cpu()
        all_embs = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            inputs = self._cpu_tokenizer(
                batch, padding=True, truncation=True, max_length=512, return_tensors="pt",
            )
            with torch.no_grad():
                outputs = self._cpu_model(**inputs)
                last_hidden = outputs.last_hidden_state
                mask = inputs["attention_mask"].unsqueeze(-1).float()
                pooled = (last_hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
                pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
            all_embs.append(pooled.cpu().numpy())
        return np.concatenate(all_embs, axis=0)

    # ── CPU 稀疏编码 ──────────────────────────────────

    def _encode_sparse_cpu(self, texts: list[str], batch_size: int = 8) -> list[dict[int, float]]:
        import torch
        self._ensure_model_cpu()
        all_results = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            inputs = self._cpu_tokenizer(
                batch, padding=True, truncation=True, max_length=512, return_tensors="pt",
            )
            with torch.no_grad():
                outputs = self._cpu_model(**inputs)
                last_hidden = outputs.last_hidden_state
                sparse_logits = (
                    torch.matmul(last_hidden, self._cpu_sparse_linear_weight.T)
                    + self._cpu_sparse_linear_bias
                ).squeeze(-1)
                sparse_logits = torch.relu(sparse_logits)
                sparse_logits = sparse_logits * inputs["attention_mask"].float()

            for b in range(len(batch)):
                token_weights: dict[int, float] = {}
                input_ids = inputs["input_ids"][b]
                for pos in range(sparse_logits.shape[1]):
                    if inputs["attention_mask"][b, pos] > 0:
                        tid = int(input_ids[pos].item())
                        w = float(sparse_logits[b, pos].item())
                        if w > 1e-6:
                            if tid not in token_weights or w > token_weights[tid]:
                                token_weights[tid] = w
                all_results.append(token_weights)
        return all_results

    # ── Multi-vector 编码 (ColBERT 风格延迟交互) ─────

    def _encode_multivector(self, texts: list[str], batch_size: int = 64) -> list["np.ndarray"]:
        import numpy as np
        import torch
        results = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            inputs = self._tokenizer(
                batch, padding=True, truncation=True, max_length=512, return_tensors="pt",
            ).to(self._device)
            with torch.no_grad():
                outputs = self._model(**inputs)
                last_hidden = outputs.last_hidden_state
            last_hidden = torch.nn.functional.normalize(last_hidden, p=2, dim=-1)
            for b in range(len(batch)):
                mask = inputs["attention_mask"][b].bool()
                results.append(last_hidden[b, mask, :].cpu().float().numpy())
        return results

    def _encode_multivector_cpu(self, texts: list[str], batch_size: int = 8) -> list["np.ndarray"]:
        import numpy as np
        import torch
        self._ensure_model_cpu()
        results = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            inputs = self._cpu_tokenizer(
                batch, padding=True, truncation=True, max_length=512, return_tensors="pt",
            )
            with torch.no_grad():
                outputs = self._cpu_model(**inputs)
                last_hidden = outputs.last_hidden_state
            last_hidden = torch.nn.functional.normalize(last_hidden, p=2, dim=-1)
            for b in range(len(batch)):
                mask = inputs["attention_mask"][b].bool()
                results.append(last_hidden[b, mask, :].cpu().float().numpy())
        return results

    # ── 稀疏编码 ────────────────────────────────────

    def _encode_sparse(self, texts: list[str], batch_size: int = 32) -> list[dict[int, float]]:
        import torch
        all_results = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            inputs = self._tokenizer(
                batch, padding=True, truncation=True, max_length=512, return_tensors="pt",
            ).to(self._device)
            with torch.no_grad():
                outputs = self._model(**inputs)
                last_hidden = outputs.last_hidden_state
                sparse_logits = (
                    torch.matmul(last_hidden, self._sparse_linear_weight.T) + self._sparse_linear_bias
                ).squeeze(-1)
                sparse_logits = torch.relu(sparse_logits)
                sparse_logits = sparse_logits * inputs["attention_mask"].float()

            for b in range(len(batch)):
                token_weights: dict[int, float] = {}
                input_ids = inputs["input_ids"][b]
                for pos in range(sparse_logits.shape[1]):
                    if inputs["attention_mask"][b, pos] > 0:
                        tid = int(input_ids[pos].item())
                        w = float(sparse_logits[b, pos].item())
                        if w > 1e-6:
                            if tid not in token_weights or w > token_weights[tid]:
                                token_weights[tid] = w
                all_results.append(token_weights)
        return all_results

    # ── 向量缓存 ────────────────────────────────────

    @staticmethod
    def _compute_records_hash(records: list[dict]) -> str:
        texts = "".join(r.get("text", "") for r in records)
        return hashlib.md5(texts.encode("utf-8")).hexdigest()

    def _try_load_cache(self) -> bool:
        manifest_path = os.path.join(self.config.vector_store_dir, "manifest.json")
        dense_path = os.path.join(self.config.vector_store_dir, "dense_embeddings.npy")
        sparse_path = os.path.join(self.config.vector_store_dir, "sparse_weights.jsonl")
        if not all(os.path.exists(p) for p in [manifest_path, dense_path, sparse_path]):
            return False
        try:
            with open(manifest_path, "r") as f:
                manifest = orjson.loads(f.read())
            expected_hash = self._compute_records_hash(self.records)
            if manifest.get("record_hash") != expected_hash:
                logger.info("向量缓存失效（文档已变更），重新编码")
                return False

            import numpy as np
            self.dense_embeddings = np.load(dense_path)

            self.sparse_weights = []
            with open(sparse_path, "r") as f:
                for line in f:
                    weights = orjson.loads(line)
                    self.sparse_weights.append({int(k): float(v) for k, v in weights.items()})

            self._build_sparse_inverted_index()
            logger.info("向量缓存加载成功: %d 个文档", len(self.records))
            return True
        except Exception as e:
            logger.warning("向量缓存加载失败，重新编码: %s", e)
            return False

    def _save_cache(self):
        os.makedirs(self.config.vector_store_dir, exist_ok=True)
        manifest = {
            "record_hash": self._compute_records_hash(self.records),
            "num_records": len(self.records),
            "created_at": time.time(),
        }
        with open(os.path.join(self.config.vector_store_dir, "manifest.json"), "w") as f:
            f.write(orjson.dumps(manifest).decode("utf-8"))

        import numpy as np
        np.save(os.path.join(self.config.vector_store_dir, "dense_embeddings.npy"), self.dense_embeddings)

        with open(os.path.join(self.config.vector_store_dir, "sparse_weights.jsonl"), "w") as f:
            for sw in self.sparse_weights:
                f.write(orjson.dumps({str(k): v for k, v in sw.items()}).decode("utf-8") + "\n")

        logger.info("向量缓存已保存到 %s", self.config.vector_store_dir)

    def _build_sparse_inverted_index(self):
        from collections import defaultdict
        self._sparse_inverted = defaultdict(list)
        for doc_idx, sw in enumerate(self.sparse_weights):
            for tid, w in sw.items():
                self._sparse_inverted[tid].append((doc_idx, w))

    # ── 文档加载 ────────────────────────────────────

    def _load_records(self) -> list[dict]:
        records: list[dict] = []
        for category, d in self.rag_dirs.items():
            if not os.path.isdir(d):
                continue
            for p in glob.glob(os.path.join(d, "**", "*"), recursive=True):
                if not os.path.isfile(p):
                    continue
                ext = os.path.splitext(p)[1].lower()
                if ext == ".jsonl":
                    jsonl_recs = self._parse_jsonl(p)
                    for r in jsonl_recs:
                        r["category"] = category
                        r["path"] = p
                    records.extend(jsonl_recs)
                    if jsonl_recs:
                        logger.info("  JSONL %s: %d 条", os.path.basename(p), len(jsonl_recs))
                    continue
                text = self._read_file(p)
                if not text or len(text.strip()) < 20:
                    continue
                chunks = self._chunk_text(text)
                for ci, chunk in enumerate(chunks):
                    records.append({
                        "text": chunk,
                        "category": category,
                        "path": p,
                        "library_name": "",
                        "source_name": "",
                        "source_type": "",
                        "tara_phase": [],
                        "knowledge_role": "",
                    })
        return records

    # ── 加载 ─────────────────────────────────────────

    def load(self, force: bool = False):
        with self._lock:
            if self._loaded and not force:
                return

            self.records = self._load_records()
            if not self.records:
                logger.warning("BGE-M3 RAG: 未找到可索引的文档")
                self._loaded = True
                return

            if self._try_load_cache():
                self._loaded = True
                return

            logger.info("BGE-M3 编码 %d 个文档 ...", len(self.records))
            self._ensure_model()
            texts = [r["text"][:512].strip() for r in self.records]
            self.dense_embeddings = self._encode_dense(texts)
            self.sparse_weights = self._encode_sparse(texts)
            self._build_sparse_inverted_index()

            self._save_cache()
            self._loaded = True
            logger.info("BGE-M3 RAG 就绪")

    # ── Cross-Encoder 重排（懒加载）───────────────────

    def _get_reranker(self):
        if self._reranker is not None:
            return self._reranker
        if not self.reranker_enabled:
            self._reranker = False
            return False
        with self._reranker_lock:
            if self._reranker is not None:
                return self._reranker
            if self.config.verify_model_hashes:
                if not self._verify_model_hashes(
                    os.path.join(self.reranker_model_path, "MANIFEST.sha256"),
                    self.reranker_model_path,
                ):
                    raise RuntimeError("Cross-encoder 模型完整性校验失败")
            try:
                import torch
                from transformers import AutoModelForSequenceClassification, AutoTokenizer
                device = self._rag_device if self._rag_device.startswith("cuda") else "cpu"
                logger.info("加载 Cross-encoder: %s (设备: %s)", self.reranker_model_path, device)
                self._reranker_tokenizer = AutoTokenizer.from_pretrained(
                    self.reranker_model_path, use_safetensors=True)
                self._reranker_model = AutoModelForSequenceClassification.from_pretrained(
                    self.reranker_model_path,
                    torch_dtype=torch.float16 if device.startswith("cuda") else torch.float32,
                    use_safetensors=True,
                ).to(device).eval()
                self._reranker_device = device
                self._reranker = True
                logger.info("Cross-encoder 重排引擎就绪 (设备: %s)", device)
            except Exception as e:
                logger.warning("Cross-encoder 加载失败 (%s)，跳过重排", e)
                self._reranker = False
        return self._reranker

    # ── 检索 ─────────────────────────────────────────

    def retrieve(self, query: str, top_k: int = 5, max_chars: int = 1800,
                 library_filter: str | list[str] | None = None,
                 tara_phase_filter: str | list[str] | None = None) -> str:
        if not self.config.enable_rag:
            return "[RAG已关闭]"
        if not self._loaded:
            self.load()
        if not self.records or self.dense_embeddings is None:
            return "[RAG为空]"

        self._ensure_model()
        q_dense = self._encode_dense([query])[0]
        q_sparse = self._encode_sparse([query])[0]

        import numpy as np

        # ── Dense 余弦相似度 ────────────────────────
        dense_scores = np.dot(self.dense_embeddings, q_dense)

        # ── Sparse 内积 ─────────────────────────────
        sparse_scores = np.zeros(len(self.records))
        for tid, qw in q_sparse.items():
            if tid in self._sparse_inverted:
                for doc_idx, dw in self._sparse_inverted[tid]:
                    sparse_scores[doc_idx] += qw * dw

        # ── library_filter ──────────────────────────
        if library_filter is not None:
            if isinstance(library_filter, str):
                filter_set = {library_filter}
            else:
                filter_set = set(library_filter)
            for i, r in enumerate(self.records):
                lib = r.get("library_name", "")
                if lib not in filter_set and lib != "":
                    dense_scores[i] = -1e9
                    sparse_scores[i] = -1e9

        # ── RRF ─────────────────────────────────────
        k = self.rrf_k
        n = len(dense_scores)
        dense_ranks = np.zeros(n, dtype=int)
        dense_order = np.argsort(-dense_scores)
        dense_ranks[dense_order] = np.arange(1, n + 1)

        sparse_ranks = np.zeros(n, dtype=int)
        sparse_order = np.argsort(-sparse_scores)
        sparse_ranks[sparse_order] = np.arange(1, n + 1)

        rrf_scores = 1.0 / (k + dense_ranks) + 1.0 / (k + sparse_ranks)

        # ── tara_phase_filter ───────────────────────
        if tara_phase_filter is not None:
            if isinstance(tara_phase_filter, str):
                filter_set = {tara_phase_filter}
            else:
                filter_set = set(tara_phase_filter)
            for i, r in enumerate(self.records):
                phases = r.get("tara_phase", [])
                if isinstance(phases, str):
                    phases = [phases]
                if not any(p in filter_set for p in phases):
                    rrf_scores[i] = -1e9

        sorted_indices = np.argsort(-rrf_scores)

        # ── Cross-Encoder 重排 ──────────────────────
        reranker_ok = self._get_reranker()
        if reranker_ok:
            candidates = [int(i) for i in sorted_indices[:self.reranker_candidates] if rrf_scores[i] > -1e8]
        else:
            candidates = [int(i) for i in sorted_indices if rrf_scores[i] > -1e8]

        if not candidates:
            return "[RAG未命中]"

        if reranker_ok and candidates:
            import torch
            pairs = [(query, self.records[idx]["text"][:512].strip()) for idx in candidates]
            # 分批推理，避免显存溢出
            all_scores = []
            bs = self.reranker_batch_size
            for start in range(0, len(pairs), bs):
                batch_pairs = pairs[start:start + bs]
                inputs = self._reranker_tokenizer(
                    batch_pairs, padding=True, truncation=True, max_length=512, return_tensors="pt",
                ).to(self._reranker_device)
                with torch.no_grad():
                    batch_scores = self._reranker_model(**inputs).logits.squeeze(-1).cpu().numpy()
                all_scores.extend(batch_scores.tolist() if hasattr(batch_scores, 'tolist') else list(batch_scores))
            rerank_scores = np.array(all_scores)
            rerank_order = sorted(range(len(candidates)), key=lambda i: rerank_scores[i], reverse=True)
            top_indices = [candidates[i] for i in rerank_order]
        else:
            top_indices = candidates

        # ── 结果组装（含 per-phase 截断长度）────────
        results: list[str] = []
        total = 0
        for idx in top_indices:
            phases = self.records[idx].get("tara_phase", [])
            if isinstance(phases, str):
                phases = [phases]
            max_len = max((SNIPPET_MAX_LENS.get(p, 500) for p in phases), default=500)
            snippet = self.records[idx]["text"][:max_len].strip()
            src = self.records[idx].get("source_name", "") or self.records[idx].get("category", "")
            line = f"[来源:{src}] {snippet}"
            if total + len(line) > max_chars:
                break
            results.append(line)
            total += len(line)
            if len(results) >= top_k:
                break

        return "\n---\n".join(results) if results else "[RAG未命中]"

    # ── R155 威胁编号匹配（后处理，无需 LLM）───────────

    def _load_r155_descriptions(self) -> tuple[list[str], list[str]]:
        """加载 R155 Annex 5 子项 description，返回 (ids, texts)。"""
        try:
            with open(self.config.r155_annex5_path, "rb") as _f:
                _r155_data = orjson.loads(_f.read())
            ids, texts = [], []
            for _sec in _r155_data.get("sections", []):
                for _threat in _sec.get("threats", []):
                    for _sub in _threat.get("sub_items", []):
                        ids.append(_sub["id"])
                        texts.append(_sub["description"])
            return ids, texts
        except Exception as e:
            logger.warning("R155 加载失败: %s", e)
            return [], []

    def _try_load_r155_cache(self, expected_hash: str):
        """尝试加载 R155 稠密缓存 (dense embeddings)。"""
        import numpy as np
        meta_path = os.path.join(self.config.vector_store_dir, "r155_manifest.json")
        dense_path = os.path.join(self.config.vector_store_dir, "r155_embeddings.npy")
        if not os.path.exists(meta_path) or not os.path.exists(dense_path):
            return None
        try:
            with open(meta_path, "r") as f:
                meta = orjson.loads(f.read())
            if meta.get("hash") != expected_hash:
                return None
            dense = np.load(dense_path)
            logger.info("R155 稠密缓存加载成功 (%d 条)", len(dense))
            return dense
        except Exception as e:
            logger.warning("R155 缓存加载失败: %s", e)
            return None

    def _save_r155_cache(self, dense, hash_val: str):
        import numpy as np

        os.makedirs(self.config.vector_store_dir, exist_ok=True)
        np.save(os.path.join(self.config.vector_store_dir, "r155_embeddings.npy"), dense)
        with open(os.path.join(self.config.vector_store_dir, "r155_manifest.json"), "w") as f:
            f.write(orjson.dumps({"hash": hash_val}).decode("utf-8"))
        logger.info("R155 稠密缓存已保存 (%d 条)", len(dense))

    def _encode_r155_dense(self, texts: list[str]) -> "np.ndarray":
        """对 R155 文本做稠密编码，优先 GPU，否则回退 CPU。"""
        import torch
        gpu_viable = False
        try:
            free, total = torch.cuda.mem_get_info()
            gpu_viable = free > 3 * 1024 ** 3
        except Exception:
            pass
        if gpu_viable:
            try:
                self._ensure_model()
                return self._encode_dense(texts)
            except (RuntimeError, AttributeError, torch.cuda.OutOfMemoryError):
                logger.info("BGE-M3 GPU 不可用，回退 CPU 编码 %d 条文本", len(texts))
        return self._encode_dense_cpu(texts)

    def match_r155(self, text: str, top_k: int = 5) -> list[str]:
        """R155 威胁编号匹配：BGE-M3 Dense cos 初筛 (>0) → Cross-encoder 重排 → 最大间隔截断。

        bge-reranker-v2-m3 对余弦相似度 > 0 的候选进行精排，
        然后用最大间隔法自动确定截断点，无需硬阈值。
        """
        if not self.config.enable_r155:
            return []
        if not text or not text.strip():
            return []

        # ── 懒加载 R155 稠密编码 ─────────────────────
        if not self._r155_ids:
            with self._lock:
                if self._r155_ids:
                    pass
                else:
                    r155_ids, r155_texts = self._load_r155_descriptions()
                    if not r155_ids:
                        return []
                    self._r155_ids = r155_ids
                    self._r155_texts = r155_texts
                    hash_val = hashlib.md5("".join(r155_texts).encode("utf-8")).hexdigest()
                    cached = self._try_load_r155_cache(hash_val)
                    if cached is not None:
                        self._r155_dense = cached
                    else:
                        try:
                            self._r155_dense = self._encode_r155_dense(r155_texts)
                            self._save_r155_cache(self._r155_dense, hash_val)
                        except Exception as e:
                            logger.warning("R155 编码失败 (%s), 跳过 R155 匹配", e)
                            self._r155_dense = None

        if self._r155_dense is None or not self._r155_ids:
            return []

        import numpy as np
        n = len(self._r155_ids)

        # ── Query 稠密编码 ───────────────────────────
        try:
            q_dense = self._encode_r155_dense([text])
        except Exception as e:
            logger.warning("R155 query 编码失败: %s", e)
            return []

        # ── Dense cosine 初筛 (保留 > 0 的候选) ──────
        dense_scores = np.dot(self._r155_dense, q_dense.squeeze(0))
        candidate_mask = dense_scores > 0
        candidate_indices = np.where(candidate_mask)[0]

        if len(candidate_indices) == 0:
            logger.info("[R155] 余弦相似度无 > 0 候选，跳过")
            return []

        # ── Cross-encoder 重排 ──────────────────────
        reranker_ok = self._get_reranker()
        if reranker_ok:
            import torch
            pairs = [(text, self._r155_texts[idx][:512].strip()) for idx in candidate_indices]
            # 分批推理，避免显存溢出
            all_ce_scores = []
            bs = self.reranker_batch_size
            for start in range(0, len(pairs), bs):
                batch_pairs = pairs[start:start + bs]
                inputs = self._reranker_tokenizer(
                    batch_pairs, padding=True, truncation=True, max_length=512, return_tensors="pt",
                ).to(self._reranker_device)
                with torch.no_grad():
                    batch_scores = self._reranker_model(**inputs).logits.squeeze(-1).cpu().numpy()
                all_ce_scores.extend(batch_scores.tolist() if hasattr(batch_scores, 'tolist') else list(batch_scores))
            ce_scores = np.array(all_ce_scores)

            ce_order = np.argsort(-ce_scores)
            sorted_indices = candidate_indices[ce_order]
            sorted_scores = ce_scores[ce_order]
            method = "CE"
        else:
            # CE 不可用时回退 dense 排序
            dense_order = np.argsort(-dense_scores[candidate_indices])
            sorted_indices = candidate_indices[dense_order]
            sorted_scores = dense_scores[candidate_indices][dense_order]
            method = "dense"

        # ── 最大间隔法截断 ───────────────────────────
        m = len(sorted_indices)
        if m == 1:
            return [self._r155_ids[int(sorted_indices[0])]]

        # 正数差分：drops[i] = sorted_scores[i] - sorted_scores[i+1]
        # 降序排列下恒 ≥ 0，值越大表示该处下降越陡
        drops = sorted_scores[:-1] - sorted_scores[1:]
        max_drop_idx = int(np.argmax(drops))
        n_take = max_drop_idx + 1

        # 边界阈值：只保留 max-gap 范围内 CE score > 0 的项
        valid = [i for i in range(n_take) if sorted_scores[i] > 0]

        # Log
        top3 = ", ".join(f"{sorted_scores[i]:.4f}" for i in range(min(3, m)))
        logger.info(
            f"[R155] {method}: candidates={m}/{n} n_take={n_take} n_valid={len(valid)} "
            f"max_drop={drops[max_drop_idx]:.4f} "
            f"top3=[{top3}]"
        )

        return [self._r155_ids[int(sorted_indices[i])] for i in valid]
