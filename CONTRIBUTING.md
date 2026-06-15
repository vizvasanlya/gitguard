# Contributing to GitGuard

Thank you for your interest in contributing to GitGuard! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/gitguard.git
   cd gitguard
   ```
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
4. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

## Development Workflow

1. Create a new branch for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and ensure tests pass:
   ```bash
   pytest tests/ -v
   ```

3. Run linters:
   ```bash
   ruff check src/ tests/
   mypy src/
   ```

4. Commit your changes with a descriptive message:
   ```bash
   git commit -m "Add feature: description of what you added"
   ```

5. Push to your fork and submit a pull request.

## Code Style

- Follow PEP 8 guidelines
- Use type hints for all function signatures
- Keep functions focused and under 50 lines when possible
- Write docstrings for public APIs
- Use meaningful variable names

## Testing

- Write tests for new functionality
- Maintain test coverage above 80%
- Use pytest fixtures for common test data
- Test both success and error cases

## Reporting Issues

- Use GitHub Issues for bug reports
- Include reproduction steps
- Provide Python version and OS information
- Include relevant error messages

## Feature Requests

- Open an issue with the "enhancement" label
- Describe the use case and expected behavior
- Consider implementation complexity

## Pull Request Guidelines

- PRs should focus on a single change
- Include tests for new functionality
- Update documentation if needed
- Ensure CI passes before requesting review

## Code of Conduct

Be respectful and constructive in all interactions.
