# Agent Build Instructions

## Project Setup

```bash
# Install dependencies (uv handles this automatically)
uv sync

# Or install in development mode
uv pip install -e .
```

## Running the CLI

```bash
# Run via uv
uv run triage --help

# Or after installation
triage --help
```

## Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src tests/ --cov-report=term-missing

# Run specific test file
uv run pytest tests/test_api.py -v
```

## Type Checking

```bash
uv run mypy src/
# or
uv run ty src/
```

## Linting and Formatting

```bash
# Format code
uv run ruff format src/

# Check linting
uv run ruff check src/

# Fix auto-fixable issues
uv run ruff check --fix src/
```

## Development Workflow

```bash
# 1. Make changes to src/
# 2. Run tests
uv run pytest

# 3. Type check
uv run mypy src/

# 4. Format and lint
uv run ruff format src/ && uv run ruff check src/

# 5. Test CLI manually
uv run triage --help
```

## Configuration

The CLI looks for API key in this order:
1. Config file: `~/.config/triage/config.toml` (or `$XDG_CONFIG_HOME/triage/config.toml`)
2. Environment variable: `TRIAGE_API_KEY`

Config file format:
```toml
api_key = "your-api-key-here"
```

## Key Learnings
- Use `uv` for all Python operations (it manages the virtualenv)
- Test against live API with care (rate limits apply)
- ZIP password for samples is always "infected"
- Target types: hash (MD5/SHA1/SHA256/SHA512/SSDEEP/TLSH), submission URL, analysis URL
