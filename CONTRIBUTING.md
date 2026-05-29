# Contributing to leakdetector

Thank you for your interest in contributing to leakdetector.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/leakdetector.git
   cd leakdetector
   ```
3. Install Go 1.26 or later.
4. Run `make build` to verify the project builds.
5. Run `make test` to verify all tests pass.
6. Run `make lint` to verify linting passes.

## Development Workflow

1. Create a feature branch from `master`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Make your changes following the coding standards below.
3. Write tests for your changes (98%+ coverage required).
4. Run the full validation suite:
   ```bash
   make lint
   make test
   make cover
   make build
   ```
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/) format:
   ```
   feat: add support for new secret pattern
   fix: correct false positive in AWS key detection
   test: add edge case tests for entropy calculation
   docs: update configuration reference
   refactor: simplify scanner pipeline
   perf: optimize regex compilation caching
   chore: update CI pipeline
   ```
6. Push your branch and open a pull request.

## Coding Standards

This project follows the [Asymmetric Effort Coding Standards](https://coding-standards.asymmetric-effort.com).

Key requirements:
- **Coverage**: 98%+ unit/integration/e2e test coverage.
- **Dependencies**: Minimize third-party dependencies. Prefer stdlib.
- **No recursion** without guaranteed tail-call optimization.
- **All queues and buffers must be bounded**.
- **Pure functions preferred**.
- **No `any` types** without explicit documentation.
- **No unresolved TODO/FIXME** comments for the current task.
- **Remove dead code**, unused imports, and unused variables.

## Pull Request Guidelines

- One logical change per PR.
- PR description must clearly explain changes and rationale.
- All CI checks must pass before merge.
- At least one review approval required.
- Security considerations must be explicitly addressed in the review.

## Reporting Bugs

Open an issue on GitHub with:
- Steps to reproduce.
- Expected vs. actual behavior.
- Version of leakdetector (`leakdetector --version`).
- Operating system and architecture.

## Security Vulnerabilities

See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE.txt).
