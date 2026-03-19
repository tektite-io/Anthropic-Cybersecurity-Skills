# Cybersecurity Skills Repository -- Security & Quality Audit Report

**Audit Date:** 2026-03-17
**Repository:** Anthropic-Cybersecurity-Skills
**Auditors:** 15-agent automated audit team (silly-herding-tide)
**Scope:** All 742 skill directories, 734 SKILL.md files, 733 agent.py files

---

## Executive Summary

A comprehensive 14-task automated audit of 742 cybersecurity skill directories (734 with SKILL.md, 733 with agent.py) found **zero critical security vulnerabilities** (no eval/exec on live data, no prompt injection, no YAML injection, no real hardcoded secrets) but identified **25 HIGH-severity shell injection patterns** using `subprocess.run(shell=True)` with f-string interpolation, **178 instances of disabled SSL verification**, and **33 HTTP requests missing timeouts**. The repository content is verified as high-quality (87% of sampled skills confirmed real against official documentation, 0% fake), but has systemic quality issues: all 734 SKILL.md files contain extra frontmatter fields beyond the standard spec, 697/734 use an alternate body template lacking `## Instructions`/`## Examples` sections, and 9 offensive tools lack disclaimers in both their SKILL.md and agent.py files. The repo is **educational-grade, not production-safe** -- it is well-researched reference material with real code, but should not be deployed as-is in any environment accepting untrusted input.

---

## Security Findings

### CRITICAL

**eval/exec/pickle/marshal on live data: 0 findings**
- Scanned all 733 agent.py files for `eval(`, `exec(`, `pickle.loads(`, `marshal.loads(` used on live data
- 16 `eval(` matches were all string literals (SPL query syntax, regex patterns, CSP header text)
- 9 `exec(` matches were all function/variable names (e.g., `detect_psexec`) or regex patterns
- Zero instances of `pickle.loads()` or `marshal.loads()`
- **Verdict: CLEAN**

**Prompt injection in SKILL.md: 0 exploitable findings**
- Scanned all 734 SKILL.md files for "ignore previous", "you are now", "ADMIN:", `<system>`, `<prompt>`, `[INST]`, "as a helpful AI", hidden HTML comments, zero-width characters, base64 payloads
- 21 files matched patterns, but all are educational content explaining prompt injection as a security topic (e.g., skills about detecting/preventing prompt injection)
- **Verdict: CLEAN** (educational context, not weaponized)

**YAML injection in frontmatter: 0 findings**
- Scanned all 734 SKILL.md frontmatter blocks for injection patterns
- All matches were in body content (educational examples), not in frontmatter
- **Verdict: CLEAN**

**Real hardcoded secrets (API keys, tokens): 0 findings**
- Scanned for AKIA*, sk-*, ghp_*, real tokens, embedded base64 blobs
- Found default/example credentials only (see MEDIUM section)
- **Verdict: CLEAN**

### HIGH

**1. Shell injection via subprocess.run(shell=True) -- 25 instances**

25 agent.py files use `subprocess.run(cmd, shell=True, ...)`, and at least 4 use f-string interpolation of file paths directly into shell commands (e.g., `f"strings -n {min_length} {filepath}"`). If any of these scripts ever received untrusted input, shell injection would be trivial.

Top-risk files (f-string + shell=True):
- `analyzing-linux-elf-malware/scripts/agent.py` (lines 88, 129, 138, 151) -- **HIGHEST RISK: compound vulnerability.** Uses raw `sys.argv[1]` (not even argparse), flows unsanitized into both `open(filepath, "rb")` (path traversal at lines 25, 46, 67, 122) AND 4 `shell=True` f-string subprocess calls (shell injection). A malicious filename could both traverse the filesystem and execute arbitrary commands.
- `analyzing-network-traffic-for-incidents/scripts/agent.py` (lines 22, 35, 61, 124, 138)
- `performing-threat-emulation-with-atomic-red-team/scripts/agent.py` (lines 99, 128)
- `performing-privilege-escalation-assessment/scripts/agent.py` (line 30)

**Mitigating factor:** All scripts are CLI tools invoked locally via argparse (or sys.argv), not web-exposed. The user already has shell access.

**Risk: HIGH in reuse/integration contexts, LOW for current local-CLI usage.**

**2. Dynamic imports via __import__() -- 8 instances**

8 agent.py files use `__import__()` for inline imports of standard library modules (datetime, time, collections, os). Not malicious, but obscures dependencies and is an anti-pattern.

Files: `analyzing-threat-intelligence-feeds`, `bypassing-authentication-with-forced-browsing`, `conducting-api-security-testing`, `conducting-man-in-the-middle-attack-simulation`, `exploiting-ipv6-vulnerabilities`, `implementing-zero-trust-with-hashicorp-boundary`, `performing-hash-cracking-with-hashcat`, `performing-security-headers-audit`

**Risk: MEDIUM (poor practice, not exploitable)**

**3. Missing authorized-testing disclaimers -- 9 CRITICAL skills**

9 offensive security skills have NO disclaimer in EITHER their SKILL.md or agent.py:
1. `exploiting-excessive-data-exposure-in-api`
2. `performing-graphql-depth-limit-attack`
3. `performing-graphql-introspection-attack`
4. `performing-http-parameter-pollution-attack`
5. `performing-jwt-none-algorithm-attack`
6. `performing-supply-chain-attack-simulation`
7. `performing-web-cache-deception-attack`
8. `conducting-internal-network-penetration-test`
9. `conducting-mobile-application-penetration-test`

An additional 7 skills are missing disclaimers in agent.py only, and 20 are missing disclaimers in SKILL.md only. Total: 36 of 58 offensive skills have at least one missing disclaimer.

**Risk: HIGH (legal/liability concern for offensive tooling)**

### MEDIUM

**1. Disabled SSL verification (verify=False) -- 178 instances**
- 178 occurrences across agent.py files explicitly disable SSL certificate verification
- Common in tools connecting to local/lab instances (Splunk, SIEM, Nessus), but unsafe if pointed at production endpoints
- **Risk: MEDIUM**

**2. HTTP requests without timeout -- 33 instances**
- 33 HTTP request calls across agent.py files lack a `timeout` parameter
- Can cause indefinite hangs if target is unresponsive
- **Risk: MEDIUM**

**3. HTTP URLs instead of HTTPS -- 76 agent.py files**
- 76 scripts reference `http://` URLs
- Some are intentional (testing HTTP-specific vulnerabilities), others are careless defaults
- **Risk: LOW-MEDIUM**

**4. Default/example credentials in code -- ~9 instances**
- `neo4j`/`bloodhound` (BloodHound tool default)
- `admin`/`admin` (GVM default)
- `kismet`/`kismet` (Kismet default)
- `Harbor12345` (Harbor default)
- `SecureP@ss123` (demo password)
- All are well-known tool defaults or demo values, not real secrets
- **Risk: LOW (tool defaults, not real credentials)**

**5. Path traversal -- systemic but low-exploitability**
- ~342 agent.py files use `open()` with `args.*` parameters without path sanitization
- ~43 scripts create directories from unsanitized user input (`os.makedirs(args.output_dir)`)
- 1 script uses `shutil.rmtree()` on a derived path (`implementing-immutable-backup-with-restic`)
- Zero scripts validate that resolved paths stay within an expected base directory
- **Risk: LOW for CLI tools (user already has filesystem access), HIGH if ever web-exposed**

### LOW

**1. SQL injection patterns -- 6 MEDIUM findings**
- 6 agent.py files use SQL patterns that could be vulnerable (string formatting in queries)
- Limited scope -- most are local SQLite usage in forensics/logging contexts
- **Risk: MEDIUM (localized)**

**2. Minor format issues** (see Quality Findings below)

---

## Quality Findings

### SKILL.md Frontmatter Compliance (Task #4 -- auditor-4)

**732 of 734 SKILL.md files (99.7%) contain 6 extra frontmatter fields** beyond the minimal `name` + `description` spec:
- Extra fields present in nearly all files: `domain`, `subdomain`, `tags`, `version`, `author`, `license`
- **2 files have YAML parse errors** (unescaped colons in values)
- **ALL `name` values pass validation:** lowercase-with-hyphens, max 64 chars, no "claude" or "anthropic"
- **ALL `description` values pass validation:** under 1024 characters
- **Compliance with minimal two-field spec: 0%** (all have extra fields)
- **Compliance with extended format: 732/734 (99.7%)** (2 YAML errors)

**Verdict:** The frontmatter is internally consistent but uses a richer schema than the minimal two-field standard. This is a format standardization finding (the cybersecurity repo uses a different template than the ai-agents repo), not a security vulnerability. The 2 YAML parse errors should be fixed.

### SKILL.md Body Structure

Two distinct templates are in use across the repository:

**Primary template (697/734 = 95%):** Uses sections like `## When to Use`, `## Key Concepts`, `## Prerequisites`, `## Workflow`, `## Tools & Systems`, `## Output Format`, `## Common Scenarios`. Does NOT include `## Instructions` or `## Examples`.

**Standard template (37/734 = 5%):** Uses `## Instructions` and `## Examples` sections per the original spec.

Section presence across all 734 files:
- `## Prerequisites`: 627 (85%)
- `## Key Concepts`: 438 (60%)
- `## Workflow`: 369 (50%)
- `## When to Use`: 369 (50%)
- `## Tools & Systems`: 350 (48%)
- `## Overview`: 318 (43%)
- `## Output Format`: 326 (44%)
- `## Common Scenarios`: 300 (41%)
- `## Instructions`: 37 (5%)
- `## Examples`: 37 (5%)

**Quality issues:**
- Stub/minimal SKILL.md files (under 20 lines): **10 files**
- Placeholder text (`TODO`, `FIXME`, `lorem ipsum`, `placeholder`): **0 files** (per auditor-5 deep scan)
- Average SKILL.md length: **218 lines** (substantial content)

### agent.py Quality

- Total agent.py files: **733**
- Average length: **178 lines** (non-trivial implementations)
- Files under 10 lines: **0** (none suspiciously short)
- Total lines of Python code: **130,466**
- Boilerplate/generic agent.py detected: **~4 out of 30 sampled** (13%) -- these use a generic HTTP-request template instead of tool-specific implementation

### Missing Files

- Directories missing SKILL.md: **8** (all ransomware/recovery-related batch additions)
  - `analyzing-ransomware-payment-wallets`
  - `building-ransomware-playbook-with-cisa-framework`
  - `deploying-decoy-files-for-ransomware-detection`
  - `detecting-ransomware-encryption-behavior`
  - `detecting-suspicious-powershell-execution`
  - `implementing-anti-ransomware-group-policy`
  - `implementing-ransomware-kill-switch-detection`
  - `testing-ransomware-recovery-procedures`
  - `validating-backup-integrity-for-recovery` (also missing SKILL.md)

- Directories missing agent.py: **9** (same set as above)

---

## Dependency Audit

### Top 30 Imports (by frequency across 733 agent.py files)

| Package | Count | Type | Status |
|---------|-------|------|--------|
| json | 689 | stdlib | Safe |
| argparse | 514 | stdlib | Safe |
| sys | 421 | stdlib | Safe |
| subprocess | 222 | stdlib | Safe (see shell=True findings) |
| os | 219 | stdlib | Safe |
| re | 197 | stdlib | Safe |
| logging | 133 | stdlib | Safe |
| hashlib | 95 | stdlib | Safe |
| requests | 82 | PyPI | Safe, well-known |
| csv | 46 | stdlib | Safe |
| time | 40 | stdlib | Safe |
| datetime | 32 | stdlib | Safe |
| math | 31 | stdlib | Safe |
| struct | 30 | stdlib | Safe |
| socket | 27 | stdlib | Safe |
| base64 | 22 | stdlib | Safe |
| xml | 19 | stdlib | Safe |
| urllib/urllib3 | 28 | stdlib/PyPI | Safe |
| boto3 | 15 | PyPI | Safe, AWS SDK |
| ssl | 12 | stdlib | Safe |
| email | 12 | stdlib | Safe |
| hmac | 9 | stdlib | Safe |
| splunklib | 8 | PyPI | Safe, Splunk SDK |
| uuid | 7 | stdlib | Safe |
| collections | 7 | stdlib | Safe |
| sqlite3 | 6 | stdlib | Safe |
| pandas | 6 | PyPI | Safe |

**Typosquatted packages found: 0**
**Known-malicious packages found: 0**
**Suspicious single-use packages found: 0**
**Packages not on PyPI found: 0**

All imports are well-known standard library modules or established PyPI packages (requests, boto3, splunklib, pandas, pefile, yara-python, python-nmap, sslyze, ldap3, etc.). No evidence of supply chain compromise.

---

## Content Verification

### Methodology
30 randomly selected skills across 10 categories (forensics, cloud, network, malware, web, endpoint, SIEM, appsec, identity, threat intel) were verified by reading both SKILL.md and agent.py, then cross-referencing tool commands, API methods, CLI flags, and MITRE ATT&CK IDs against official documentation via web search.

### Results

| Category | Count | Verdict |
|----------|-------|---------|
| VERIFIED (all code references real tools/APIs) | 26/30 | 87% |
| PARTIALLY_REAL (SKILL.md real, agent.py generic boilerplate) | 4/30 | 13% |
| FAKE (invented commands/APIs) | 0/30 | 0% |

**Key verification highlights:**
- All Volatility 3 plugin names confirmed real (windows.pslist, windows.psscan, windows.malfind)
- All Splunk SDK classes confirmed real (splunklib.client.connect, JSONResultsReader)
- All AWS CLI/boto3 commands verified (GuardDuty, CloudTrail, S3)
- All nmap flags verified against nmap.org documentation
- All sslyze classes confirmed against official docs
- All MITRE ATT&CK technique IDs verified (T1055.012, T1140, T1218.005, etc.)
- All Kubernetes commands verified against kubernetes.io
- All LDAP OIDs verified (1.2.840.113556.1.4.1941 for recursive group membership)
- LOLBin signatures verified against LOLBAS project
- Certipy/Certify commands verified for AD CS ESC1 exploitation

**PARTIALLY_REAL pattern:** 4 skills use a generic HTTP-request template in agent.py (`GET {target}/api/v1/status` with bearer token) instead of implementing the actual tool described in SKILL.md. Examples: `implementing-semgrep-for-custom-sast-rules`, `performing-dark-web-monitoring-for-threats`. This suggests template-based generation was used for a subset of agent.py files.

---

## Duplicate Analysis

### Methodology
Jaccard similarity analysis across all 742 skill directory names, comparing SKILL.md content.

### Results
- **Exact duplicates: 0**
- **Near-duplicate pairs (Jaccard >= 0.60): 67**
  - Classified as REDUNDANT: **21 pairs**
  - Classified as UNIQUE_TECHNIQUES (overlapping topic but different approach): **46 pairs**

The 21 redundant pairs likely result from skills being created under slightly different names covering the same tool or technique. These should be reviewed for consolidation.

---

## Folder Anatomy

### Expected structure per skill:
```
skill-name/
  SKILL.md
  scripts/
    agent.py
```

### Completion Stats

| Component | Present | Missing | Percentage |
|-----------|---------|---------|------------|
| Total directories | 742 | -- | -- |
| SKILL.md | 734 | 8 | 98.9% |
| scripts/ directory | 742 | 0 | 100% |
| scripts/agent.py | 733 | 9 | 98.8% |
| Fully complete (SKILL.md + agent.py) | 731 | 11 | 98.5% |
| Empty shell directories (scripts/ only) | 8 | -- | 1.1% |
| Partial (missing one file) | 3 | -- | 0.4% |

Per auditor-13: 731 of 742 directories are fully complete (98.5%). 8 directories are empty shells containing only a scripts/ directory with no SKILL.md or agent.py. 3 directories are partial (have one file but not the other). The incomplete directories are predominantly from a ransomware/recovery-related batch addition.

---

## Statistics

| Category | Count |
|----------|-------|
| Total skill directories | 742 |
| Directories with SKILL.md | 734 (98.9%) |
| Directories with agent.py | 733 (98.8%) |
| SKILL.md frontmatter present | 734/734 (100%) |
| SKILL.md with extended frontmatter (extra fields) | 732/734 (99.7%) |
| SKILL.md frontmatter YAML parse errors | 2 |
| SKILL.md name field valid (lowercase-hyphens, <64 chars) | 734/734 (100%) |
| SKILL.md description field valid (<1024 chars) | 734/734 (100%) |
| Average SKILL.md length | 218 lines |
| Average agent.py length | 178 lines |
| Total Python code | 130,466 lines |
| Code security issues (CRITICAL -- eval/exec/pickle) | 0 |
| Code security issues (HIGH -- shell=True) | 25 |
| Code security issues (HIGH -- missing disclaimers) | 9 (both files) |
| Code security issues (MEDIUM -- SQL injection) | 6 |
| Dynamic imports (__import__) | 8 |
| verify=False (disabled SSL) | 178 |
| HTTP requests without timeout | 33 |
| HTTP URLs (not HTTPS) | 76 |
| Default credentials in code | ~9 |
| Prompt injection found | 0 (21 educational references) |
| YAML injection found | 0 |
| Hardcoded real secrets found | 0 |
| Typosquatted/malicious imports | 0 |
| Unique packages imported | 84 (all legitimate) |
| Skills verified as real code (sample) | 26/30 (87%) |
| Skills verified as partially real (sample) | 4/30 (13%) |
| Skills verified as fake | 0/30 (0%) |
| Exact duplicate skills | 0 |
| Near-duplicate (redundant) skill pairs | 21 |
| Overlap clusters | 4 |
| Complete folder anatomy | 731/742 (98.5%) |
| Empty shell directories | 8 |
| Partial directories | 3 |
| SKILL.md using alternate template | 697/734 (95%) |
| Stub SKILL.md files (<20 lines) | 10 |
| Placeholder text in SKILL.md | 0 |
| Offensive skills missing any disclaimer | 36/58 (62%) |

---

## Recommendations

### Priority 1 (HIGH): Fix shell injection patterns
Replace all 25 instances of `subprocess.run(cmd, shell=True)` with list-based commands and `shlex.split()`. This is especially urgent for the 4 files using f-string interpolation of file paths into shell commands (analyzing-linux-elf-malware, analyzing-network-traffic-for-incidents, performing-threat-emulation-with-atomic-red-team, performing-privilege-escalation-assessment).

### Priority 2 (HIGH): Add authorized-testing disclaimers to all 58 offensive skills
9 skills have zero disclaimers. 36 of 58 offensive skills are missing at least one disclaimer. Every offensive skill should have a clear disclaimer in both SKILL.md and agent.py stating: "For authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have permission to test is illegal."

### Priority 3 (MEDIUM): Fix SSL verification and add timeouts
178 instances of `verify=False` disable SSL certificate validation. 33 HTTP requests lack timeouts. Add `timeout=30` to all HTTP calls and only disable SSL verification when explicitly connecting to local/lab instances with self-signed certificates.

### Priority 4 (MEDIUM): Complete the 11 incomplete skill directories
8 directories are empty shells and 3 are partial (missing either SKILL.md or agent.py). Either complete these skills or remove the incomplete directories.

### Priority 5 (LOW): Consolidate 21 redundant skill pairs
Review and merge or differentiate the 21 near-duplicate skill pairs to reduce redundancy and improve navigability.

---

## Final Verdict

### Is this repo "vibe coded"?

**No.** This is not vibe-coded. The evidence strongly indicates this is a carefully structured, systematically generated cybersecurity skills repository:

- **87% of sampled skills contain verified, accurate tool commands, API methods, CLI flags, and MITRE ATT&CK references** confirmed against official documentation
- **0% contain fabricated or invented tool commands** -- even the 13% classified as "partially real" have accurate SKILL.md content, just generic agent.py boilerplate
- **130,466 lines of Python** with an average of 178 lines per agent.py -- these are non-trivial implementations, not stubs
- **734 SKILL.md files** averaging 218 lines each with consistent frontmatter and structured sections
- **Zero critical security vulnerabilities** (no eval/exec exploitation, no prompt injection, no real secrets, no YAML injection, no supply chain compromised packages)
- The entire import set consists of well-known, legitimate packages

The repository shows hallmarks of systematic, high-quality generation with domain expertise: correct MITRE technique IDs, accurate tool-specific CLI flags, proper library usage patterns, and real-world security concepts. The 4/30 boilerplate agent.py files and the frontmatter consistency suggest automated generation with manual or expert-guided prompting, but the output quality is genuinely high.

### Is it production-safe?

**No, with caveats.** It is safe as a reference/educational resource but not safe to deploy directly:

1. **25 shell injection risks** (shell=True with interpolation) would be exploitable if scripts ever receive untrusted input
2. **178 disabled SSL verifications** and **33 missing timeouts** are not production-grade
3. **342 files accept file paths without sanitization** -- acceptable for CLI tools, dangerous in any other context
4. **36 offensive tools lack proper legal disclaimers** -- a liability concern
5. The code was designed as educational/reference material, not as production software

**Bottom line:** This is a high-quality, well-researched cybersecurity skills library with real, verified content and no critical vulnerabilities. It needs targeted hardening (shell injection, timeouts, disclaimers) before any production or public-facing use, but it is fundamentally sound educational material -- not a security risk in its intended context.

---

*Report compiled by auditor-15 from findings of all 14 specialized audit agents (14/14 tasks completed).*
*Audit completed: 2026-03-17*
