# Contributing to ERKLIG

Thank you for your interest in contributing to ERKLIG! 🎉

**ERKLIG is 100% open source and community-driven.** We believe in the power of collective security knowledge and welcome contributors of all skill levels.

---

## 🌟 Why Contribute?

- **Make the web safer**: Help detect and prevent malware
- **Learn security**: Understand how backdoors and web shells work
- **Build your portfolio**: Contributions are public and visible
- **Join a community**: Connect with security researchers worldwide

---

## 🎯 Contribution Types

### 🐛 Bug Reports
- Unexpected behaviors
- Error messages
- False positive/negative detections
- Platform-specific issues

### 💡 Feature Requests
- New detection signatures
- Performance improvements
- UI/UX enhancements
- Integration ideas

### 📝 Documentation
- README improvements
- Usage examples
- Translations
- Tutorials

### 🔧 Code Contributions
- Bug fixes
- New features
- Tests
- Refactoring

### 🔍 Security Signatures
- New malware patterns
- Obfuscation techniques
- Webshell signatures
- Regional threats

---

## 🚀 Getting Started

### 1. Fork the Repository

Click the "Fork" button on [github.com/iamcanturk/erklig](https://github.com/iamcanturk/erklig)

### 2. Clone Your Fork

```bash
git clone https://github.com/YOUR_USERNAME/erklig.git
cd erklig
```

### 3. Create a Branch

```bash
# For features
git checkout -b feature/amazing-feature

# For bug fixes
git checkout -b fix/bug-description

# For documentation
git checkout -b docs/doc-update

# For new signatures
git checkout -b signature/new-webshell
```

### 4. Make Changes

Edit the code, test thoroughly.

### 5. Commit

```bash
git add .
git commit -m "feat: add amazing feature"
```

**Commit Message Format:**
| Prefix | Usage |
|--------|-------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation |
| `refactor:` | Code restructuring |
| `test:` | Adding tests |
| `sig:` | New signature |

### 6. Push

```bash
git push origin feature/amazing-feature
```

### 7. Open Pull Request

Go to GitHub and open a Pull Request with a clear description.

---

## 📋 Code Standards

### Bash Script Guidelines

1. **ShellCheck Compliant**
   ```bash
   # Install ShellCheck
   brew install shellcheck  # macOS
   apt install shellcheck   # Ubuntu
   
   # Run check
   shellcheck erklig.sh
   ```

2. **Function Naming**: Use `snake_case`
   ```bash
   draw_header()
   scan_files()
   generate_report()
   ```

3. **Variable Naming**
   - `UPPER_CASE` for globals/constants
   - `lower_case` for locals
   ```bash
   GLOBAL_CONFIG="value"
   local file_path="$1"
   ```

4. **Comments**: Explain complex logic
   ```bash
   # Calculate file entropy
   # High entropy (>7) indicates obfuscated code
   calculate_entropy() {
       ...
   }
   ```

5. **Error Handling**: Check critical operations
   ```bash
   if ! grep -q "pattern" "$file"; then
       echo "Pattern not found"
       return 1
   fi
   ```

6. **Quoting**: Always quote variables
   ```bash
   # Good
   echo "$variable"
   
   # Bad
   echo $variable
   ```

---

## 🔍 Adding New Signatures

New malware signatures are crucial for ERKLIG's effectiveness!

### Steps to Add a Signature

1. **Identify the pattern**
   ```php
   // Example: New webshell variant
   <?php if(isset($_POST['xyz'])){@eval($_POST['xyz']);} ?>
   ```

2. **Create regex pattern**
   ```regex
   @eval\s*\(\s*\$_POST
   ```

3. **Add to PATTERN variable** in `erklig.sh`
   ```bash
   PATTERN="...|@eval\s*\(\s*\$_POST"
   ```

4. **Test for false positives**
   - Run against clean WordPress/Laravel/Joomla installation
   - Check popular plugins

5. **Document in PR**
   - Source of the signature
   - Example malware
   - False positive testing results

### Signature Categories

| Category | Examples |
|----------|----------|
| Command Execution | `shell_exec`, `passthru`, `system` |
| Code Evaluation | `eval`, `assert`, `create_function` |
| Obfuscation | `base64_decode`, `gzinflate`, `str_rot13` |
| Known Shells | `FilesMan`, `WSO`, `c99`, `r57` |
| Network | `fsockopen`, `curl_exec`, `file_get_contents` |

---

## 🧪 Testing

### Basic Testing

```bash
# Make script executable
chmod +x erklig.sh

# Run basic scan
./erklig.sh

# Test in sample directory
cd tests/samples && ../../erklig.sh
```

### Create Test Files

```bash
mkdir -p tests/samples

# Create a safe PHP file
echo '<?php echo "Hello World"; ?>' > tests/samples/safe.php

# Create a suspicious file
echo '<?php eval($_POST["cmd"]); ?>' > tests/samples/malicious.php
```

### Test Checklist

- [ ] Script runs without errors
- [ ] Known malware is detected
- [ ] Safe files don't trigger false positives
- [ ] Progress bar works correctly
- [ ] Output is readable

---

## 📬 Pull Request Guidelines

### PR Title Format

```
feat: Add entropy-based detection
fix: Resolve false positive for WordPress core
docs: Update installation instructions
sig: Add new c99shell variant signature
```

### PR Description Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Signature update
- [ ] Documentation

## Testing
How was this tested?

## Checklist
- [ ] ShellCheck passes
- [ ] Tested on Linux
- [ ] Tested on macOS
- [ ] No new false positives
- [ ] Documentation updated
```

---

## 🐛 Reporting Bugs

### Create an Issue

1. Go to [Issues](https://github.com/iamcanturk/erklig/issues)
2. Click "New Issue"
3. Use this template:

```markdown
## Bug Description
Clear description of the bug.

## Steps to Reproduce
1. Step one
2. Step two
3. See error

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Environment
- OS: [e.g., Ubuntu 22.04]
- Bash version: [e.g., 5.1]
- ERKLIG version: [e.g., v1.3.0]

## Error Output
```
Paste any error messages here
```
```

---

## 💬 Community

### Get Help

- **GitHub Issues**: Technical questions
- **Twitter**: [@iamcanturk](https://twitter.com/iamcanturk)
- **Website**: [iamcanturk.dev](https://iamcanturk.dev)

### Share Your Success

Found malware using ERKLIG? We'd love to hear about it!

- Tweet with #ERKLIG
- Write a blog post
- Share in security communities

---

## 🏆 Recognition

All contributors are:

- Listed in our README
- Credited in release notes
- Part of our growing community!

---

## 📜 Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Provide constructive feedback
- Focus on collaboration
- No harassment or discrimination

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

<p align="center">
  <strong>Thank you for helping make the web more secure! ⚔️</strong>
</p>

<p align="center">
  <sub>
    <a href="https://github.com/iamcanturk/erklig">GitHub</a> •
    <a href="https://twitter.com/iamcanturk">Twitter</a> •
    <a href="https://iamcanturk.dev">Website</a>
  </sub>
</p>
