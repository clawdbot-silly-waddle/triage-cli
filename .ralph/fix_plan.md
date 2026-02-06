# Ralph Fix Plan

## High Priority
- [ ] Set up Python 3.13 project with uv (pyproject.toml, project structure)
- [ ] Implement API client for tria.ge with authentication (config file + env var)
- [ ] Implement target URL/hash parsing (auto-detect type)
- [ ] Implement hash search (MD5, SHA1, SHA256, SHA512, SSDEEP, TLSH)
- [ ] Implement `sample` subcommand to download samples (decrypt ZIP, delete after extraction)
- [ ] Implement `domains` subcommand to download contacted domains/URLs (deduplicate across analyses)
- [ ] Implement `dumps` subcommand to download dynamic analysis dumped files (handle filename conflicts)

## Medium Priority
- [ ] Add proper error handling and user-friendly messages
- [ ] Add CLI tests with mocked API responses
- [ ] Test against live tria.ge API with test key
- [ ] Create README with usage examples

## Low Priority
- [ ] Add progress bars for downloads
- [ ] Add verbose/debug logging option

## Completed
- [x] Project initialization

## Test URLs for Development
- https://tria.ge/260206-mrmcdshv5h/behavioral1
- https://tria.ge/260206-mrmcdshv5h/
- https://tria.ge/260206-mr9spahv7f/behavioral2

## Test Hashes for Development
- MD5: bf458fab974aa1888eb064082711cd8c
- SHA1: 16a75d57993c1591d6b52a8740ca85768a13ab49
- SHA256: 318e4d4421ce1470da7a23ece3db5e6e4fe9532e07751fc20b1e35d7d7a88ec7
