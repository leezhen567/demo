"""支持包模式和 VS Code 直接运行当前文件。"""

if __package__:
    from .cli import main
else:
    # 直接执行 automotive_tara/__main__.py 时，Python 只会把包目录本身
    # 放入 sys.path；补入项目根目录后再使用绝对包导入。
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from automotive_tara.cli import main


if __name__ == "__main__":
    main()
