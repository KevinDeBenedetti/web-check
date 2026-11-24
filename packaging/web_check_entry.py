"""PyInstaller entry point of the standalone web-check binary (see `make bin`)."""

from cli.main import app

if __name__ == "__main__":
    app()
