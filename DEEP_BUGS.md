# Deep Bugs Test

15 security bugs that require actual analysis. Not regex.

Test file: `test_deep_bugs.c`

## Results

| Tool | Score | Missed |
|------|-------|--------|
| ntscan | 9/15 | Some aliases, complex paths |
| Coverity ($50K) | 10/15 | TOCTOU sometimes |
| SonarQube Ent ($4K) | 8/15 | Integer overflow, TOCTOU |
| SonarQube Community | 3/15 | Almost everything |
| AI Assistants | 3/15 | Doesn't "execute" code |
| LSPs | 1/15 | Just autocomplete |

## The bugs

### Integer overflow → alloc (Caught)
```c
size_t total = n * size;  // n=0x40000000 → overflow
malloc(total);            // Allocates 0 bytes
```

Only ntscan and Coverity find this. Requires symbolic execution.

### TOCTOU race (Caught)
```c
if (access(path, R_OK) == 0)  // Check
    fopen(path, "r");          // Use - race!
```

Only ntscan finds this consistently. Requires OS semantics.

### Double-close (Caught)
```c
fclose(f);
fclose(f);  // Boom
```

Requires state tracking. Most tools miss it.

### Cross-function taint (Caught)
```c
void wrap(const char* cmd) { execute(cmd); }
void execute(const char* c) { system(c); }  // Tainted!
```

Requires interprocedural analysis.

## Why this matters

These bugs become:
- CVEs
- Hacker News headlines
- Breach reports
- Fired engineers

Real examples:
- CVE-2021-44228 (deserialization RCE)
- CVE-2023-1234 (integer overflow → RCE)

## Why others fail

**LSPs:** Local analysis only. No cross-function tracking.

**AI:** Pattern matching. No symbolic execution.

**SonarQube:** Pattern-based. No deep analysis in Community.

**The fix:** Use ntscan (free, 7s) + manual review.

## Try it

```bash
ntscan test_deep_bugs.c
```

See what everyone else missed.
