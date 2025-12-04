# Test Environment Files

This directory contains simulated malware files for testing ERKLIG.

## ⚠️ WARNING

These files contain **simulated malicious code patterns**. They are:
- **NON-FUNCTIONAL** - They won't actually execute harmful operations
- **FOR TESTING ONLY** - Used to verify ERKLIG's detection capabilities
- **NOT REAL MALWARE** - Just code patterns that match known threats

## File List

| File | Type | Expected Detection |
|------|------|-------------------|
| `config.php` | Legitimate | ❌ Should NOT detect |
| `index.html` | Legitimate | ❌ Should NOT detect |
| `wp-includes/functions.php` | Legitimate (whitelisted) | ❌ Should NOT detect |
| `wp-content/uploads/2024/image_gallery.php` | Command Execution | ✅ CRITICAL |
| `wp-content/themes/theme1/footer.php` | Obfuscation | ✅ CRITICAL |
| `wp-content/plugins/plugin1/helpers.php` | Known Webshell | ✅ CRITICAL |
| `wp-content/plugins/plugin1/class-utils.php` | High Entropy | ✅ HIGH |
| `images/photo.jpg.php` | Double Extension | ✅ HIGH |
| `tmp/cache_manager.php` | Network Backdoor | ✅ CRITICAL |
| `wp-content/uploads/2024/thumb_001.php` | One-liner | ✅ CRITICAL |

## Testing

Run ERKLIG against this directory:

```bash
./erklig ./testenv/testbed
```

Expected results:
- 7 threats detected
- 0 false positives from legitimate files
- wp-includes should be skipped (whitelist)
