# Feature: Original Filenames for Dumped Files

## Problem

When downloading dumped files via the `dumps` subcommand, the current implementation uses the `filename` field from the API response. However, this is often a triage-internal generated name like `fstream-1.dat` rather than the original file name.

For example, for target `https://tria.ge/260211-mq6pmsfx4g/behavioral1`, the dumped files have these original paths:
```
/data/data/com.tencent.mm/app_DynamicOptDex/Uwmt.json
/data/data/com.tencent.mm/app_DynamicOptDex/Uwmt.json
/data/data/com.tencent.mm/app_DynamicOptDex/oat/Uwmt.json.cur.prof
/data/user/0/com.tencent.mm/app_DynamicOptDex/Uwmt.json
```

The original filename `Uwmt.json` should be preserved in the downloaded file name.

## Requirements

1. **Extract original filename**: Use the original file path/name from the dumped file metadata instead of the generated `filename` field.

2. **Handle duplicate filenames**: When multiple dumped files have the same original name (e.g., `Uwmt.json` appears 4 times in the example above), implement a smart naming strategy to prevent file name conflicts while keeping the original filename at the end.

   Possible approaches:
   - Append a counter: `Uwmt.json`, `Uwmt-2.json`, `Uwmt-3.json`, etc.
   - Include parent directory info: `app_DynamicOptDex-Uwmt.json`, `oat-Uwmt.json.cur.prof`, etc.
   - Use a combination: Include some path components to disambiguate

3. **Preserve file extensions**: Ensure the original file extension is preserved correctly.

## API Response Structure

The `get_dumped_files` endpoint returns a list of dumped file objects. Each object contains:
- `id`: The file ID for downloading
- `filename`: The triage-internal generated name (e.g., `fstream-1.dat`)
- Additional metadata including the original file path

The original file path can be extracted from the dumped file metadata to derive the true original filename.

## Example Output

For the example above with 4 files all originally named `Uwmt.json`:

Current behavior (bad):
- `fstream-1.dat`
- `fstream-2.dat`
- `fstream-3.dat`
- `fstream-4.dat`

Desired behavior (good):
- `Uwmt.json`
- `Uwmt-2.json` (or `app_DynamicOptDex-Uwmt.json`)
- `Uwmt-3.json` (or `oat-Uwmt.json.cur.prof`)
- `Uwmt-4.json` (or `app_DynamicOptDex-Uwmt-2.json`)

## Files to Modify

- `src/triage/cli.py`: The `dumps` command implementation
- `src/triage/api.py`: May need to extract or expose the original file path from metadata
