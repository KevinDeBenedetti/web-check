# Contributing to Vigil

Thank you for your interest in contributing to Vigil! 🎉

## 🚀 Getting Started

1. **Fork the repository**
2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/vigil.git
   cd vigil
   ```
3. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 📋 Development Guidelines

### Code Style

- **Shell scripts:** Follow [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
- **Use shellcheck:** Run `make lint` before committing
- **Add comments:** Document functions with purpose, arguments, and outputs
- **Use meaningful names:** Variables and functions should be self-explanatory

### Testing Your Changes

```bash
# Verify prerequisites
make check

# Test with a safe target
make quick TARGET=https://example.com

# Run linter
make lint
```

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat(scanner): add support for custom nuclei templates
fix(report): handle empty scan results gracefully
docs(readme): add CI/CD integration examples
```

## 🔧 Pull Request Process

1. **Update documentation** if you're changing functionality
2. **Run the linter:** `make lint`
3. **Test your changes** with at least one scan
4. **Create a Pull Request** with a clear description of changes
5. **Wait for review** - maintainers will review your PR

## 🐛 Reporting Issues

When reporting bugs, please include:

- **Environment:** OS, Docker version
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Logs:** Relevant output from `outputs/<scan>/logs/`

## 💡 Feature Requests

We welcome feature requests! Please:

1. Check if the feature already exists or is planned
2. Open an issue with the `enhancement` label
3. Describe the use case and expected behavior

## ⚠️ Security Considerations

- **Never commit real scan results** - they may contain sensitive data
- **Test only on systems you own** or have permission to scan
- **Report security issues privately** - email the maintainer instead of opening a public issue

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make Vigil better! 🔒
