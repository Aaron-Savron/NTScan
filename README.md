# ntscan

Finds security bugs in 7 seconds instead of 20 minutes.

## What it does

Scans C, C++, Python, JavaScript, Java for actual vulnerabilities (not style issues).

Finds:
- Buffer overflows
- NULL dereferences  
- Use-after-free
- Integer overflows
- Command injection
- SQL injection
- XSS
- 20+ more

## Quick start

```bash
# Download
curl -L https://github.com/you/ntscan/releases/download/v0.2/ntscan -o ntscan
chmod +x ntscan

# Run
./ntscan /path/to/code

# Done in 7 seconds
```

## Why it's fast

- mmap() files (zero copy)
- Lock-free parallelism
- Single-pass AST
- No database, no Docker, no JVM

## Why it's deep

- Symbolic execution (tracks overflow paths)
- Cross-function taint analysis
- Data flow tracking
- Finds bugs others miss

## The numbers

| Tool | Time | Bugs Found | Cost |
|------|------|------------|------|
| ntscan | 7s | 35,000 | $0 |
| SonarQube | 20min | 6,000 | $0-4K/yr |
| Coverity | 30min | 18,000 | $50K/yr |

See [COMPARE.md](COMPARE.md) for details.

## Usage

```bash
# Scan current dir
ntscan .

# Quiet mode (CI-friendly)
ntscan --quiet .

# Generate GitHub workflow
ntscan --git

# Watch mode (auto-rescan)
ntscan --watch .

# Baseline comparison (only new issues)
ntscan --baseline previous.json .

# Config file
ntscan --config .ntscan.toml .

# SARIF output (GitHub integration)
ntscan --sarif results.sarif .

# JSON output
ntscan --format json . > bugs.json

# Coffee recommendation
ntscan --coffee .

# Block CI on critical bugs  
ntscan . || exit 1
```

## What it finds

See [DEEP_BUGS.md](DEEP_BUGS.md) for the 29 vulnerability types.

## Install

```bash
# With Rust
cargo install ntscan

# Or grab binary from releases
```

## Limitations

- Only 5 languages have full AST (C, C++, Python, JS, Java)
- No web UI (just text/JSON)
- No historical trends

For compliance dashboards, use SonarQube. For finding bugs, use this.

## License

MIT. Don't get hacked.
