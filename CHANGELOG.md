# Changelog

## [0.1.1](https://github.com/KevinDeBenedetti/web-check/compare/v0.1.0...v0.1.1) (2026-01-13)


### 🚀 Features

* add .gitignore, CODE_OF_CONDUCT.md, CONTRIBUTING.md, LICENSE, SECURITY.md and update Makefile ([f7742e9](https://github.com/KevinDeBenedetti/web-check/commit/f7742e909ba3af0feb722a0ee82566c1858868ff))
* add Button, Card, Checkbox, Input, and Label components for UI consistency ([3b3e31a](https://github.com/KevinDeBenedetti/web-check/commit/3b3e31a7399d1e976efaa4c91ae8e712181a018b))
* add CODE_OF_CONDUCT.md, CONTRIBUTING.md, LICENSE, and SECURITY.md files ([8587893](https://github.com/KevinDeBenedetti/web-check/commit/8587893da53586f8e071f58d343a642402305db4))
* add database integration and initial migration setup ([36c4081](https://github.com/KevinDeBenedetti/web-check/commit/36c40819b661c93734c3899317d170bc1fdb42fe))
* add environment configuration, update .gitignore, and improve type hints in services ([054676d](https://github.com/KevinDeBenedetti/web-check/commit/054676db404c07d4f1a78fb19cbefdc24ae8c314))
* add GitHub Copilot instructions to copilot-instructions.md ([838cb06](https://github.com/KevinDeBenedetti/web-check/commit/838cb06f355628f7f443830207cb5999d39beb21))
* add Release Please configuration and CI/CD workflows for release management ([f888bd7](https://github.com/KevinDeBenedetti/web-check/commit/f888bd7c697c89e1d3db61173a43db3af0934fa1))
* add ScanStats and ScanTimeline components for displaying scan results and progress ([3b3e31a](https://github.com/KevinDeBenedetti/web-check/commit/3b3e31a7399d1e976efaa4c91ae8e712181a018b))
* add Tooltip component for enhanced UI interactions ([c3c7161](https://github.com/KevinDeBenedetti/web-check/commit/c3c71610fc3a9f39793be468404d00e1704c9ea8))
* create reusable Badge component for consistent UI ([3b3e31a](https://github.com/KevinDeBenedetti/web-check/commit/3b3e31a7399d1e976efaa4c91ae8e712181a018b))
* define tool configurations and categories for scanning tools ([3b3e31a](https://github.com/KevinDeBenedetti/web-check/commit/3b3e31a7399d1e976efaa4c91ae8e712181a018b))
* Implement modular report generation for security scanner ([b64503c](https://github.com/KevinDeBenedetti/web-check/commit/b64503c127b55231956d37ac3c5f5f9cacda2493))
* implement SeverityBadge component with improved styling ([3b3e31a](https://github.com/KevinDeBenedetti/web-check/commit/3b3e31a7399d1e976efaa4c91ae8e712181a018b))
* implement ToolSelector component for better tool management in ScanForm ([c3c7161](https://github.com/KevinDeBenedetti/web-check/commit/c3c71610fc3a9f39793be468404d00e1704c9ea8))
* Implement Vigil Security Scanner with multiple scanning modules ([19e7b9a](https://github.com/KevinDeBenedetti/web-check/commit/19e7b9a873f0534395c5b4cab5de82ceb9998a73))
* initialize web application with React, Vite, and Tailwind CSS ([43111b5](https://github.com/KevinDeBenedetti/web-check/commit/43111b5e49e1cf8cd44ca70597d600116acf0a33))
* update README for English localization and improve clarity in error messages ([c3c7161](https://github.com/KevinDeBenedetti/web-check/commit/c3c71610fc3a9f39793be468404d00e1704c9ea8))


### 🐛 Bug Fixes

* **ci:** fix Docker builds for GitHub Actions ([b54c6ab](https://github.com/KevinDeBenedetti/web-check/commit/b54c6ab6fd6be09714a9b1938bf2904afb49a815))
* **ci:** synchronize GitHub Actions workflow with local Makefile ([69b4800](https://github.com/KevinDeBenedetti/web-check/commit/69b4800eefbb86472c75877d495574a5ac3526e8))
* correct indentation in help target of Makefile ([62a3e25](https://github.com/KevinDeBenedetti/web-check/commit/62a3e258bacf8d755ab392c2afcfb29c3e7ba8d0))
* enhance API service with error logging and multiple scan execution ([3b3e31a](https://github.com/KevinDeBenedetti/web-check/commit/3b3e31a7399d1e976efaa4c91ae8e712181a018b))
* refactor and enhance security scanner components ([e9d2ada](https://github.com/KevinDeBenedetti/web-check/commit/e9d2adaa4fc603dce8f3746fd3e6080e61bad245))
* update configuration comments for clarity in settings.conf ([c3c7161](https://github.com/KevinDeBenedetti/web-check/commit/c3c71610fc3a9f39793be468404d00e1704c9ea8))
* update ScanResult component for English localization ([c3c7161](https://github.com/KevinDeBenedetti/web-check/commit/c3c71610fc3a9f39793be468404d00e1704c9ea8))


### ♻️ Code Refactoring

* enhance error messages in sslyze and zap scanner services ([c3c7161](https://github.com/KevinDeBenedetti/web-check/commit/c3c71610fc3a9f39793be468404d00e1704c9ea8))
* improve code readability and formatting across multiple components ([b71fe53](https://github.com/KevinDeBenedetti/web-check/commit/b71fe532917e37bc01d05315fcfdaabdfd6e92ef))
* rename project name ([e8182b5](https://github.com/KevinDeBenedetti/web-check/commit/e8182b5867b9783631b1a310edc419bf82038389))
* rename Vigil Security Scanner to Web-Check Security Scanner ([f3ad2ea](https://github.com/KevinDeBenedetti/web-check/commit/f3ad2eafcd382698ac47fad07bbfa61da42c2abc))
* replace Pyright with Ty for type checking and clean up code ([424915c](https://github.com/KevinDeBenedetti/web-check/commit/424915c130154fb75ca02980692f21ae45df58ac))
* update tool descriptions and categories for consistency in tools.ts ([c3c7161](https://github.com/KevinDeBenedetti/web-check/commit/c3c71610fc3a9f39793be468404d00e1704c9ea8))


### 📚 Documentation

* add md doc ([6c91887](https://github.com/KevinDeBenedetti/web-check/commit/6c918875dfef7cff5c935d278699acddb2872ab4))
