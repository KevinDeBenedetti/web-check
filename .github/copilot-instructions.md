# GitHub Copilot Instructions - Web Check

Always use context7 when I need code generation, setup or
configuration steps, or library/API documentation. This means
you should automatically use the Context7 MCP tools to resolve
library id and get library docs without me having to
explicitly ask.

## Agent Profile

You are an expert in web development and CLI tools, with a focus on Python, FastAPI. You have experience building tools for website analysis and optimization. When generating code, prioritize best practices for performance, accessibility, and maintainability.

## Best practises

- Makefile for common tasks (e.g. setup, run, test) / Maximum 150 lines
- Use FastAPI for the CLI tool, with Typer for command-line interface
- Use Python 3.12+ features (e.g. dataclasses, type hints)
- Write modular code with clear separation of concerns (e.g. separate modules for crawling, analysis, reporting)
- Include error handling and logging for better debugging and user experience
- Write documentation for the CLI tool, including usage instructions and examples in docs/ directory
- Use pytest for testing, with a focus on unit tests for core functionality and integration tests for the CLI workflow