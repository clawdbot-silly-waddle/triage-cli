# Triage CLI Specification

## Overview

A Python 3.13 CLI tool for interacting with the tria.ge malware analysis API.

## API Reference

- API Documentation: https://tria.ge/docs/
- Base URL: https://api.tria.ge/v0/

## Configuration

### API Key Priority (highest to lowest)

1. Config file: `~/.config/triage/config.toml`
2. Environment variable: `TRIAGE_API_KEY`

### Config File Format

```toml
api_key = "your-api-key-here"
```

The config file directory should be created if it doesn't exist. The config file itself should be gitignored.

## CLI Structure

```
triage <subcommand> <target> [prefix]
```

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `sample` | Download the malware sample (decrypted) |
| `domains` | Download list of contacted domains/URLs |
| `dumps` | Download dynamic analysis dumped files |

### Target Types (Auto-Detected)

1. **Sample Hash**: Supports MD5, SHA1, SHA256, SHA512, SSDEEP, TLSH
   - Example: `318e4d4421ce1470da7a23ece3db5e6e4fe9532e07751fc20b1e35d7d7a88ec7`

2. **Submission URL**: Points to a submission (contains all analyses)
   - Example: `https://tria.ge/260206-mrmcdshv5h/`
   - Pattern: `https://tria.ge/<submission-id>/`

3. **Analysis URL**: Points to a specific analysis within a submission
   - Example: `https://tria.ge/260206-mrmcdshv5h/behavioral1`
   - Pattern: `https://tria.ge/<submission-id>/<analysis-name>`

### Prefix Argument

Optional prefix for output files/directories:

- `triage sample <hash> mysample` → downloads to `mysample-<filename>`
- `triage domains <url> out/` → downloads to `out/<filename>`
- `triage dumps <url> output/myfamily` → downloads to `output/myfamily-<uniqueid>-<filename>`

Prefix rules:
- No prefix: current directory (`.`)
- Path ending in `/`: directory prefix
- Plain string: filename prefix
- Supports `~` for home directory and `/` for absolute paths

## Subcommand Details

### `sample` Subcommand

Download malware samples. When API returns encrypted ZIP:
1. Download the ZIP
2. Extract with password "infected"
3. Delete the ZIP
4. Keep only the decrypted sample

Deduplication: When multiple analyses match the hash, download from any one (they're the same file).

### `domains` Subcommand

Download lists of contacted domains/URLs from dynamic analysis.

Deduplication: If target resolves to multiple analyses, merge and deduplicate domain lists.

Output format: One domain/URL per line, plain text file.

### `dumps` Subcommand

Download dumped files from dynamic analysis (the "Downloads" section).

Filename conflict resolution:
- If multiple files would have the same name (from different analyses/submissions):
  - Add unique identifier after user prefix: `<prefix>-<submission-id>-<analysis-name>-<filename>`
  - Or: `<prefix>-<uniqueid>-<filename>`

## Target Resolution Logic

```
if target looks like a hash:
    - Search for submissions with matching sample hash
    - Return all matching submissions with their analyses
elif target is tria.ge URL:
    - Parse submission ID and optional analysis name
    - Return specific submission or analysis
```

## Hash Detection

Detect hash type by length and pattern:

| Type | Length | Pattern |
|------|--------|---------|
| MD5 | 32 | hex |
| SHA1 | 40 | hex |
| SHA256 | 64 | hex |
| SHA512 | 128 | hex |
| SSDEEP | variable | format like `98304:...` |
| TLSH | 72 (T1) or 76 (T2) | starts with T |

## Deduplication Rules

### For `sample`:
- Same hash = same file
- Download from first available analysis only

### For `domains`:
- Collect domains from all matching analyses
- Merge lists and remove duplicates
- Sort alphabetically before output

### For `dumps`:
- Downloads can come from multiple analyses
- Files with same name from different analyses need unique prefixes
- Preserve original filenames with unique analysis identifier

## Error Handling

- Invalid target: Clear error message explaining expected formats
- API errors: Propagate with context (rate limits, auth failures, not found)
- Network errors: Retry with backoff, then fail with clear message
- Missing API key: Clear instructions on how to configure

## Testing

### Test API Key

For development: `063a1a04f12f3ef23fd4ea6fd8db6d4b4f2ad73f`

⚠️ This key should NOT be committed to git.

### Test URLs

- https://tria.ge/260206-mrmcdshv5h/behavioral1
- https://tria.ge/260206-mrmcdshv5h/
- https://tria.ge/260206-mr9spahv7f/behavioral2

### Test Hashes

- MD5: `bf458fab974aa1888eb064082711cd8c`
- SHA1: `16a75d57993c1591d6b52a8740ca85768a13ab49`
- SHA256: `318e4d4421ce1470da7a23ece3db5e6e4fe9532e07751fc20b1e35d7d7a88ec7`
- SHA512: `7dfe0089a4d7de8ed35f667523bfacefc713a66a976ee16f9398df21c7c15d676e12e7ac71b1560990f61a43bcb0d4f882bae52bf6e9597ff2da5e64bce4bc20`
- SSDEEP: `98304:0utyj7T/GBqO7KAP4I0qIKXh6V+F3OK12tAC7zjZRFJ+YvX:14rWf7lgI0qJU+FIzj7FJF`
- TLSH: `T13416237AFF8DE43AD023E439D164A8438818415C8514FF672B25A75C8EEAC819367FED`

## Technology Requirements

- Python 3.13+
- Full type annotations
- `uv` for package management
- CLI framework: Click or typer (whichever is more ergonomic)
- HTTP client: httpx (async-capable, modern)
- ZIP handling: standard library zipfile
- Config: toml library

## Out of Scope

The CLI should NOT implement:
- Sample submission
- Account management
- YARA rule management
- Report generation beyond the specified outputs
- Any other API endpoints not explicitly required
