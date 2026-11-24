"""PyInstaller entry point of the standalone my-check binary (see `make bin`)."""

from my_check.cli import app

if __name__ == "__main__":
    app()
