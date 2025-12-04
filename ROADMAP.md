# ERKLIG Development Roadmap

This document outlines the development roadmap for ERKLIG Backdoor Analysis System.

## 🎉 v2.0.0 - Mighty Engine (Released)

**Major milestone achieved!** ERKLIG has been completely rewritten in Go, bringing:
- ⚡ 10x faster scanning with parallel goroutines
- 🔍 30+ malware signature patterns
- 📊 Entropy-based obfuscation detection
- 📑 Multiple report formats (TXT, JSON, HTML)
- 🎨 Professional dark-theme HTML reports
- 🐚 Bash version preserved as `erklig-lite.sh`

## 📊 Overview

| Phase | Focus Area | Target | Status |
|-------|------------|--------|--------|
| Phase I | Efficiency & Reliability | Speed and accuracy improvements | ✅ Completed |
| Phase II | Advanced Threat Detection | Anomaly-based detection | ✅ Completed |
| Phase III | User Experience | Professional reporting | ✅ Completed |
| Phase IV | Enterprise Features | Advanced integrations | 📋 Planned |

---

## 🎯 False Positive Prevention Strategy

One of ERKLIG's primary goals is to **minimize false positives** while maintaining high detection rates. Here's our comprehensive strategy:

### Current Implementation (v2.0.0 - Go)

| Feature | Description | Status |
|---------|-------------|--------|
| Directory Whitelist | Exclude known safe directories (vendor/, node_modules/) | ✅ Implemented |
| Extension Filtering | Only scan web-relevant file types | ✅ Implemented |
| Interactive Review | Manual confirmation for each detection | ✅ Implemented |
| Metadata Display | Show file info for informed decisions | ✅ Implemented |
| Parallel Scanning | Multi-threaded scanning with goroutines | ✅ Implemented |
| Entropy Analysis | Detect obfuscated/encrypted code | ✅ Implemented |
| Permission Check | Flag dangerous file permissions | ✅ Implemented |
| JSON Reports | Machine-readable output format | ✅ Implemented |
| HTML Reports | Professional dark-theme reports | ✅ Implemented |

### Planned Improvements

#### 1. CMS Auto-Detection
```
Detect CMS type → Apply appropriate whitelist → Reduce false positives by ~80%
```

| CMS | Detection Method | Whitelist Directories |
|-----|-----------------|----------------------|
| WordPress | wp-config.php, wp-includes/ | wp-admin/, wp-includes/, wp-content/themes/*/lib/ |
| Joomla | configuration.php | administrator/includes/, libraries/ |
| Drupal | sites/default/settings.php | core/, vendor/, modules/contrib/ |
| Laravel | artisan, composer.json | vendor/, storage/framework/, bootstrap/cache/ |
| Magento | app/etc/local.xml | vendor/, lib/, pub/static/ |

#### 2. Signature Context Analysis

Instead of simple pattern matching, analyze the **context** of detected patterns:

```php
// FALSE POSITIVE - Error handling in framework
try {
    eval($userCode);  // This is flagged, but it's in a try-catch
} catch (Exception $e) {
    log_error($e);
}

// TRUE POSITIVE - Raw eval with user input
$code = $_POST['code'];
eval($code);  // Direct user input = HIGH RISK
```

**Implementation:**
- Check if dangerous function is wrapped in security measures
- Analyze variable origin (user input vs internal)
- Consider surrounding code context

#### 3. Entropy-Based Scoring

| Entropy Score | Interpretation | Action |
|---------------|----------------|--------|
| 0-4 | Normal code | Skip |
| 4-6 | Slightly unusual | Low priority |
| 6-7 | Suspicious | Medium priority |
| 7-8 | Likely obfuscated | High priority |

#### 4. Community Signature Database

- Crowdsourced signature updates
- False positive reports feedback loop
- Regional threat intelligence

---

## ⚙️ Phase I: Script Efficiency & Reliability

> This phase focuses on making the script faster and more accurate.

### I.1 Performance Optimization ✅
**Priority:** 🔴 High | **Status:** Completed

**Description:**
Replace `grep -r` with targeted `find` command scanning only web file extensions.

**Target Extensions:**
- `.php`, `.php3`, `.php4`, `.php5`, `.phtml`
- `.asp`, `.aspx`, `.ascx`
- `.js`, `.jsx`
- `.html`, `.htm`, `.inc`
- `.py`, `.pl`, `.cgi`

**Expected Improvement:** 60-80% speed increase on large filesystems

---

### I.2 Whitelist System ✅
**Priority:** 🔴 High | **Status:** Completed

**Description:**
Automatic exclusion of known safe directories from popular CMS and frameworks.

**Excluded Directories:**
```
WordPress:
  - /wp-includes/
  - /wp-admin/
  
Joomla:
  - /libraries/
  - /administrator/includes/
  
Laravel:
  - /vendor/
  - /storage/framework/
  
General:
  - /node_modules/
  - /.git/
```

**Expected Improvement:** 70% reduction in false positives

---

### I.3 Date-Based Filtering ✅
**Priority:** 🟡 Medium | **Status:** Completed

**Description:**
Option to scan only files modified within a specific timeframe.

**Usage:**
```bash
./erklig --days 30 -t /var/www  # Last 30 days
./erklig --days 7 -t /var/www   # Last week
./erklig -t /var/www            # All files (default)
```

**Warning:** Old threats may be missed with this option.

---

### I.4 Enhanced Output Format ✅
**Priority:** 🟡 Medium | **Status:** Completed

**Description:**
Rich output including detection reason and file metadata.

| Field | Example |
|-------|---------|
| File Path | `/var/www/html/uploads/shell.php` |
| Detection Reason | `eval() with user input` |
| Last Modified | `2024-01-15 14:32:01` |
| Risk Level | `CRITICAL` |

**Example Output:**
```
[CRITICAL] /var/www/html/uploads/shell.php
           Reason: eval(), base64_decode(), shell_exec()
           Modified: 2024-01-15 14:32:01
           Entropy: 7.2 (suspicious)
```

---

## 🛡️ Phase II: Advanced Threat Detection

> This phase enables detection beyond signature-based scanning.

### II.1 High Entropy Detection ✅
**Priority:** 🔴 High | **Status:** Completed

**Description:**
Calculate file entropy to detect obfuscated or encrypted code. Implemented in Go with Shannon entropy calculation.

**Detection Example:**
```php
// High entropy (suspicious)
eval(gzinflate(base64_decode('eJzLSM3JyVcozy/KSQEAGgsEHQ==')));
```

**Implementation:**
```bash
# Entropy calculation (0-8 scale, >7 = suspicious)
calculate_entropy() {
    local file="$1"
    cat "$file" | fold -w1 | sort | uniq -c | \
    awk '{p=$1/NR; e-=p*log(p)/log(2)} END {print e}'
}
```

---

### II.2 Short Variable Detection ✅
**Priority:** 🟡 Medium | **Status:** Completed

**Description:**
Detect single-character or meaningless variable names commonly used in obfuscated malware. Included in signature patterns.

**Suspicious Example:**
```php
$a=$_POST[0];
$b=$_GET['x'];
@$a($b);  // Dynamic function call
```

**Detection Regex:**
```regex
\$[a-z]{1,2}\s*=\s*\$_(POST|GET|REQUEST|COOKIE)
```

---

### II.3 Permission Anomaly Check ✅
**Priority:** 🟡 Medium | **Status:** Completed

**Description:**
Flag files with dangerous permissions in web directories.

**Checks:**
- `777` or `666` permissions
- Non-standard ownership (not www-data/apache/nginx)
- SUID/SGID bits on web files

---

### II.4 Single-Line Malware Detection ✅
**Priority:** 🟢 Low | **Status:** Completed

**Description:**
Detect ultra-compact malware hidden in single lines. Included in signature patterns.

**Example:**
```php
<?php @eval($_POST['cmd']); ?>
<?=`$_GET[c]`?>
```

**Detection Criteria:**
- File < 10 lines
- Contains dangerous function
- Has external input

---

## 📊 Phase III: User Experience & Reporting

> Professional-grade user interface and reporting.

### III.1 Syntax Highlighting ✅
**Priority:** 🟢 Low | **Status:** Completed

**Description:**
Use `bat` or `vim -R` for code viewing with syntax highlighting.

**Priority Order:**
1. `bat` (if available) - Modern, colorful
2. `batcat` (Ubuntu) - bat alternative
3. `less -N` - Fallback with line numbers

---

### III.2 Progress Indicator ✅
**Priority:** 🟡 Medium | **Status:** Completed

**Description:**
Visual progress bar during scanning.

**Example:**
```
[████████████░░░░░░░░] 60% (120/200)
Scanning: /var/www/html/wp-content/uploads/2024/image.php
```

---

### III.3 Report Templates ✅
**Priority:** 🔴 High | **Status:** Completed

**Description:**
Generate professional reports in multiple formats.

**Usage:**
```bash
./erklig -t /var/www --json --html -o threat_report
```

**Supported Formats:**
- Text (`.txt`) - Simple text report
- HTML (`.html`) - Professional dark-theme report with statistics
- JSON (`.json`) - Machine-readable for integrations

**HTML Report Features:**
- Dark theme with modern UI
- Threat statistics summary
- Color-coded severity levels
- File path and match details
- Scan metadata and timestamps

---

## 📅 Release Timeline

```
v1.3.0 (Bash)       v2.0.0 (Go)         v2.5.0              v3.0.0
      |                |                   |                   |
      v                v                   v                   v
[Whitelist]      [Go Rewrite]        [Config File]       [Web UI]
[Extensions]     [Parallel Scan]     [YAML Signatures]   [Real-time]
[Progress Bar]   [Entropy]           [API Server]        [Cloud]
                 [HTML Reports]      [CI/CD Integration]
                 [JSON Export]
```

---

## 🏷️ Version Planning

| Version | Features | Target |
|---------|----------|--------|
| v1.3.0 | Whitelist, Extensions, Progress (Bash) | ✅ Released |
| v2.0.0 | Go rewrite, Entropy, Reports, Parallel scanning | ✅ Released |
| v2.5.0 | Config file, YAML signatures, API server | Q1 2025 |
| v3.0.0 | Web UI, Real-time monitoring, Cloud integration | Q2 2025 |

---

## 💡 Community Ideas

We welcome feature requests! Open an issue on GitHub to suggest:

- New detection signatures
- Whitelist additions
- Integration ideas
- UI improvements

---

## 📞 Contact

- **GitHub Issues**: [Report bugs or request features](https://github.com/iamcanturk/erklig/issues)
- **Twitter**: [@iamcanturk](https://twitter.com/iamcanturk)
- **Website**: [iamcanturk.dev](https://iamcanturk.dev)

---

*This document is regularly updated. Last update: December 2024*

---

## 🆕 Phase IV: Enterprise Features (Planned)

### IV.1 YAML Configuration File
**Priority:** 🔴 High | **Status:** Planned

**Description:**
External configuration file for custom settings.

```yaml
# erklig.yaml
scan:
  extensions: [php, js, py]
  exclude_dirs: [vendor, node_modules]
  max_file_size: 10MB
  
signatures:
  custom:
    - pattern: "my_custom_pattern"
      severity: high
      description: "Custom threat"

reporting:
  format: [html, json]
  output_dir: ./reports
```

### IV.2 REST API Server
**Priority:** 🟡 Medium | **Status:** Planned

**Description:**
Run ERKLIG as a service with REST API.

```bash
./erklig serve --port 8080
```

**Endpoints:**
- `POST /scan` - Start a new scan
- `GET /scan/{id}` - Get scan status
- `GET /report/{id}` - Download report

### IV.3 CI/CD Integration
**Priority:** 🟡 Medium | **Status:** Planned

**Description:**
GitHub Actions, GitLab CI, Jenkins plugins.

```yaml
# .github/workflows/security.yml
- name: ERKLIG Security Scan
  uses: iamcanturk/erklig-action@v2
  with:
    target: ./src
    fail-on: critical
```

### IV.4 Real-time File Monitoring
**Priority:** 🟢 Low | **Status:** Planned

**Description:**
Watch directories for new/modified files and scan automatically.

```bash
./erklig watch -t /var/www --webhook https://slack.com/...
```
