# PyPI Submission Guide

## Prerequisites

1. Create account at https://pypi.org
2. Generate API token at https://pypi.org/manage/account/token/
3. Install build tools:

```bash
pip install build twine
```

## Build

```bash
cd /home/droid/gitproject/gitguard
python -m build
```

This creates:
- `dist/gitguard-0.1.0.tar.gz` (source)
- `dist/gitguard-0.1.0-py3-none-any.whl` (wheel)

## Test Upload (TestPyPI)

```bash
twine upload --repository testpypi dist/*
```

Test install:
```bash
pip install --index-url https://test.pypi.org/simple/ gitguard
```

## Production Upload (PyPI)

```bash
twine upload dist/*
```

## Verify

```bash
pip install gitguard
gitguard --version
```

## Update Version

1. Update version in `pyproject.toml`:
```toml
version = "0.2.0"
```

2. Update `src/gitguard/__init__.py`:
```python
__version__ = "0.2.0"
```

3. Update `CHANGELOG.md`

4. Rebuild and upload:
```bash
rm -rf dist/
python -m build
twine upload dist/*
```

## GitHub Release

1. Go to https://github.com/gitguard/gitguard/releases
2. Click "Create a new release"
3. Tag: `v0.1.0`
4. Title: `v0.1.0 - Initial Release`
5. Upload `dist/gitguard-0.1.0.tar.gz`
6. Publish
