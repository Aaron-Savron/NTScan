# ntscan Features

## New CLI Options

```bash
# Quiet mode (CI-friendly)
ntscan --quiet .
# Output: "8 critical, 7 high, 0 medium in 1 file (15 issues)"

# Watch mode (auto-rescan on changes)
ntscan --watch .

# Baseline comparison (only new issues)
ntscan --baseline previous-scan.json .

# Config file
ntscan --config .ntscan.toml .

# SARIF output (GitHub integration)
ntscan --sarif results.sarif .
```

## Config File (.ntscan.toml)

```toml
extensions = ["c", "cpp", "py", "js"]
severity = "medium"
threads = 8
format = "text"
ignore = ["vendor/.*", "build/.*"]
```

## Progress Bar

Shows for scans > 50 files:
```
[████████████████████░░░░░░░░░░] 342/536 files (67%)
```

## GitHub Integration

1. Copy `.github/workflows/ntscan.yml`
2. Push to repo
3. See results in Security tab
4. PR annotations appear automatically

## SARIF Output

Standard format for security tools. Works with:
- GitHub Code Scanning
- GitLab Security Dashboard
- Azure DevOps

Example output:
```json
{
  "ruleId": "ntscan/buffer_overflow",
  "level": "error",
  "message": { "text": "strcpy is dangerous" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "src/main.c" },
      "region": { "startLine": 42 }
    }
  }]
}
```

## Baseline Scanning

Track only NEW issues:
```bash
# Save baseline
ntscan --format json . > baseline.json

# Compare future scans
ntscan --baseline baseline.json .
```

Perfect for CI - only block on new vulnerabilities, ignore existing debt.

## All Improvements Added

- Progress bar for large scans
- Fix pluralization (1 file vs 2 files)
- Add --quiet mode
- Better error messages (file read errors shown)
- Sarif output for GitHub
- Config file support (.ntscan.toml)
- Baseline support (--baseline)
- --watch mode (simple 2s polling)
- Terminal-responsive output
- GitHub Actions workflow example
