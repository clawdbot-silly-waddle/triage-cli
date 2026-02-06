# Triage CLI

A Python CLI tool for interacting with the [tria.ge](https://tria.ge) malware analysis API.

## Features

- Download malware samples (automatically decrypted from password-protected ZIP)
- Download lists of contacted domains/URLs from dynamic analysis
- Download dumped files from dynamic analysis
- Support for multiple target types: hashes (MD5, SHA1, SHA256, SHA512, SSDEEP, TLSH) and tria.ge URLs
- Deduplication of results when multiple analyses match
- Ergonomic CLI with positional arguments and optional file prefixes

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd triage-cli

# Install with uv
uv sync

# Or install in development mode
uv pip install -e .
```

## Configuration

The CLI looks for your API key in this order:

1. **Environment variable** (highest priority):
   ```bash
   export TRIAGE_API_KEY="your-api-key-here"
   ```

2. **Config file** at `~/.config/triage/config.toml`:
   ```toml
   api_key = "your-api-key-here"
   ```

## Usage

### Download a Sample

Download a malware sample by hash or URL:

```bash
# By hash
triage sample 318e4d4421ce1470da7a23ece3db5e6e4fe9532e07751fc20b1e35d7d7a88ec7

# By tria.ge URL
triage sample https://tria.ge/260206-mrmcdshv5h/

# With custom output prefix
triage sample <hash> mysample    # Saves as mysample-<filename>
triage sample <hash> output/     # Saves to output/<filename>
```

The sample is downloaded as a password-protected ZIP, automatically extracted using the password "infected", and the ZIP is deleted.

### Download Contacted Domains

Download lists of contacted domains/URLs from dynamic analysis:

```bash
# From a specific analysis
triage domains https://tria.ge/260206-mrmcdshv5h/behavioral1

# From all analyses in a submission
triage domains https://tria.ge/260206-mrmcdshv5h/

# By hash (collects from all matching analyses)
triage domains 318e4d4421ce1470da7a23ece3db5e6e4fe9532e07751fc20b1e35d7d7a88ec7

# With custom output
triage domains <target> output/  # Saves to output/domains.txt
```

Domains are deduplicated across all matching analyses and sorted alphabetically.

### Download Dumped Files

Download dumped files from dynamic analysis:

```bash
# From a specific analysis
triage dumps https://tria.ge/260206-mrmcdshv5h/behavioral1

# From all analyses in a submission
triage dumps https://tria.ge/260206-mrmcdshv5h/

# By hash (collects from all matching analyses)
triage dumps 318e4d4421ce1470da7a23ece3db5e6e4fe9532e07751fc20b1e35d7d7a88ec7

# With custom prefix
triage dumps <target> output/     # Saves to output/<submission>-<analysis>-<filename>
triage dumps <target> myprefix    # Saves as myprefix-<submission>-<analysis>-<filename>
```

## Supported Target Types

### Hashes

All common hash formats are auto-detected:

- **MD5**: `bf458fab974aa1888eb064082711cd8c`
- **SHA1**: `16a75d57993c1591d6b52a8740ca85768a13ab49`
- **SHA256**: `318e4d4421ce1470da7a23ece3db5e6e4fe9532e07751fc20b1e35d7d7a88ec7`
- **SHA512**: `7dfe0089a4d7de8ed35f667523bfacefc713a66a976ee16f9398df21c7c15d67...`
- **SSDEEP**: `98304:0utyj7T/GBqO7KAP4I0qIKXh6V+F3OK12tAC7zjZRFJ+YvX:14rWf7lgI0qJU+FIzj7FJF`
- **TLSH**: `T13416237AFF8DE43AD023E439D164A8438818415C8514FF672B25A75C8EEAC819367FED`

### URLs

- **Submission URL**: `https://tria.ge/<submission-id>/`
  - Points to a submission containing all analyses
  - Example: `https://tria.ge/260206-mrmcdshv5h/`

- **Analysis URL**: `https://tria.ge/<submission-id>/<analysis-name>`
  - Points to a specific analysis within a submission
  - Example: `https://tria.ge/260206-mrmcdshv5h/behavioral1`

## Development

```bash
# Run tests
uv run pytest

# Run specific test file
uv run pytest tests/test_target.py -v

# Type checking
uv run mypy src/

# Format code
uv run ruff format src/
```

## API Reference

- API Documentation: https://tria.ge/docs/
- Base URL: `https://api.tria.ge/v0/`

## License

[Add your license here]
