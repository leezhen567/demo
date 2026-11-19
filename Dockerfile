FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 GRADIO_ANALYTICS_ENABLED=False
COPY pyproject.toml README.md ./
COPY automotive_tara ./automotive_tara
COPY subprojects/web_demo ./subprojects/web_demo
COPY docs ./docs
RUN pip install --no-cache-dir '.[ui]'
EXPOSE 7860
CMD ["python", "-m", "automotive_tara.demo", "--host", "0.0.0.0", "--port", "7860"]
