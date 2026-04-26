# GitHub Integration

ntscan integrates with GitHub via SARIF - the standard format for security tools.

## What You Get

- **Security tab integration**: Issues appear in GitHub's Security > Code scanning alerts
- **PR annotations**: Security issues show up in pull request diffs
- **Trending**: Track security issues over time
- **Severity filtering**: Filter by critical/high/medium/low in GitHub UI

## Setup (2 minutes)

### 1. Copy the workflow file

```bash
cp .github/workflows/ntscan.yml.example .github/workflows/ntscan.yml
```

Or create `.github/workflows/ntscan.yml`:

```yaml
name: Security Scan
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
    - uses: actions/checkout@v4
    
    - name: Download ntscan
      run: |
        curl -L https://github.com/YOUR_USERNAME/ntscan/releases/latest/download/ntscan -o ntscan
        chmod +x ntscan
    
    - name: Run ntscan
      run: ./ntscan --sarif results.sarif . || true
    
    - name: Upload to GitHub
      uses: github/codeql-action/upload-sarif@v4
      with:
        sarif_file: results.sarif
```

### 2. Update the download URL

Replace `YOUR_USERNAME` with your GitHub username or organization.

### 3. Commit and push

```bash
git add .github/workflows/ntscan.yml
git commit -m "Add ntscan security scanning"
git push
```

## How It Works

1. **Every push/PR**: ntscan runs automatically
2. **SARIF output**: Results converted to GitHub's standard format
3. **upload-sarif**: GitHub ingests the results
4. **Security tab**: Issues appear with line numbers and severity

## Features in GitHub

### PR Annotations
```
Warning: Critical: Buffer overflow in main.c:42
```

### Security Tab
Browse all issues:
- Filter by severity
- Mark as false positive
- Track resolution status
- Export reports

### Trending
See if security issues are increasing or decreasing over time.

## Advanced: Baseline Scanning

Only show NEW issues in PRs (not existing technical debt):

```yaml
- name: Run ntscan with baseline
  run: |
    # Download baseline from main branch
    curl -L https://raw.githubusercontent.com/YOUR_USERNAME/REPO/main/baseline.json -o baseline.json || true
    
    # Scan with baseline comparison
    ./ntscan --baseline baseline.json --sarif results.sarif . || true
```

## SARIF Format

ntscan generates standard SARIF 2.1.0:

```json
{
  "ruleId": "ntscan/buffer_overflow",
  "level": "error",
  "message": { "text": "strcpy is dangerous" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "src/main.c" },
      "region": { "startLine": 42, "startColumn": 5 }
    }
  }]
}
```

This works with:
- GitHub Code Scanning
- GitLab Security Dashboard
- Azure DevOps
- Any SARIF-compatible tool

## Troubleshooting

### "Resource not accessible by integration"
Add to workflow:
```yaml
permissions:
  security-events: write
```

### No results appearing
Check Actions tab → Security Scan → upload-sarif step

### False positives
Mark as "false positive" in Security tab. Future scans will respect this.

## Comparison: GitHub CodeQL vs ntscan

| Feature | CodeQL | ntscan |
|---------|--------|--------|
| Setup | Complex | 1 workflow file |
| Speed | 10+ min | 7 seconds |
| Cost | Free (public) | Free |
| Languages | 10+ | 5 |
| Depth | Very deep | Deep enough |
| Custom rules | Yes | Not yet |

**Use both:**
- CodeQL for compliance and comprehensive analysis
- ntscan for fast feedback in PRs

## Next Steps

1. Add the workflow
2. Run it once
3. Check Security tab
4. Fix critical issues
5. Add badge to README:

```markdown
[![Security Scan](https://github.com/YOU/REPO/actions/workflows/ntscan.yml/badge.svg)](https://github.com/YOU/REPO/actions)
```

Done. Your code is now continuously scanned for security issues.
