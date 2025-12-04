/*
Package cms provides CMS detection and core file verification.
*/
package cms

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CMSType represents the type of CMS detected
type CMSType string

const (
	CMSWordPress CMSType = "wordpress"
	CMSJoomla    CMSType = "joomla"
	CMSDrupal    CMSType = "drupal"
	CMSLaravel   CMSType = "laravel"
	CMSMagento   CMSType = "magento"
	CMSUnknown   CMSType = "unknown"
)

// CMSInfo contains information about the detected CMS
type CMSInfo struct {
	Type      CMSType `json:"type"`
	Version   string  `json:"version"`
	Path      string  `json:"path"`
	CoreFiles int     `json:"core_files"`
}

// FileVerification represents the verification result of a core file
type FileVerification struct {
	FilePath     string `json:"file_path"`
	ExpectedHash string `json:"expected_hash"`
	ActualHash   string `json:"actual_hash"`
	IsModified   bool   `json:"is_modified"`
	IsCore       bool   `json:"is_core"`
}

// WordPressChecksums represents the WordPress checksums API response
type WordPressChecksums struct {
	Checksums map[string]string `json:"checksums"`
}

// Detector handles CMS detection and verification
type Detector struct {
	httpClient *http.Client
	cacheDir   string
}

// NewDetector creates a new CMS detector
func NewDetector(cacheDir string) *Detector {
	return &Detector{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cacheDir:   cacheDir,
	}
}

// DetectCMS detects the CMS type in the given directory
func (d *Detector) DetectCMS(path string) CMSInfo {
	info := CMSInfo{
		Type: CMSUnknown,
		Path: path,
	}

	// Check WordPress
	if version := d.detectWordPress(path); version != "" {
		info.Type = CMSWordPress
		info.Version = version
		return info
	}

	// Check Joomla
	if version := d.detectJoomla(path); version != "" {
		info.Type = CMSJoomla
		info.Version = version
		return info
	}

	// Check Drupal
	if version := d.detectDrupal(path); version != "" {
		info.Type = CMSDrupal
		info.Version = version
		return info
	}

	// Check Laravel
	if version := d.detectLaravel(path); version != "" {
		info.Type = CMSLaravel
		info.Version = version
		return info
	}

	return info
}

// detectWordPress checks for WordPress installation
func (d *Detector) detectWordPress(path string) string {
	versionFile := filepath.Join(path, "wp-includes", "version.php")
	content, err := os.ReadFile(versionFile)
	if err != nil {
		return ""
	}

	// Extract version from $wp_version = '6.4.2';
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, "$wp_version") {
			parts := strings.Split(line, "'")
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// detectJoomla checks for Joomla installation
func (d *Detector) detectJoomla(path string) string {
	// Check for Joomla 4.x+
	manifestFile := filepath.Join(path, "administrator", "manifests", "files", "joomla.xml")
	if content, err := os.ReadFile(manifestFile); err == nil {
		if version := extractXMLVersion(string(content)); version != "" {
			return version
		}
	}

	// Check for older Joomla
	versionFile := filepath.Join(path, "libraries", "src", "Version.php")
	if content, err := os.ReadFile(versionFile); err == nil {
		// Look for const MAJOR_VERSION, MINOR_VERSION, etc.
		return extractJoomlaVersion(string(content))
	}

	return ""
}

// detectDrupal checks for Drupal installation
func (d *Detector) detectDrupal(path string) string {
	// Drupal 8/9/10
	composerFile := filepath.Join(path, "core", "lib", "Drupal.php")
	if content, err := os.ReadFile(composerFile); err == nil {
		// Extract VERSION constant
		if strings.Contains(string(content), "const VERSION") {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				if strings.Contains(line, "const VERSION") {
					parts := strings.Split(line, "'")
					if len(parts) >= 2 {
						return parts[1]
					}
				}
			}
		}
	}
	return ""
}

// detectLaravel checks for Laravel installation
func (d *Detector) detectLaravel(path string) string {
	composerFile := filepath.Join(path, "vendor", "laravel", "framework", "src", "Illuminate", "Foundation", "Application.php")
	if content, err := os.ReadFile(composerFile); err == nil {
		// Extract VERSION constant
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.Contains(line, "const VERSION") {
				parts := strings.Split(line, "'")
				if len(parts) >= 2 {
					return parts[1]
				}
			}
		}
	}
	return ""
}

// GetWordPressChecksums fetches checksums from WordPress API
func (d *Detector) GetWordPressChecksums(version string) (map[string]string, error) {
	// Check cache first
	cacheFile := filepath.Join(d.cacheDir, fmt.Sprintf("wp-checksums-%s.json", version))
	if data, err := os.ReadFile(cacheFile); err == nil {
		var checksums WordPressChecksums
		if json.Unmarshal(data, &checksums) == nil {
			return checksums.Checksums, nil
		}
	}

	// Fetch from API
	url := fmt.Sprintf("https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=en_US", version)
	resp, err := d.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch checksums: %w", err)
	}
	defer resp.Body.Close()

	var checksums WordPressChecksums
	if err := json.NewDecoder(resp.Body).Decode(&checksums); err != nil {
		return nil, fmt.Errorf("failed to decode checksums: %w", err)
	}

	// Cache the result
	if d.cacheDir != "" {
		os.MkdirAll(d.cacheDir, 0755)
		data, _ := json.Marshal(checksums)
		os.WriteFile(cacheFile, data, 0644)
	}

	return checksums.Checksums, nil
}

// VerifyWordPressCore verifies WordPress core files against official checksums
func (d *Detector) VerifyWordPressCore(path, version string) ([]FileVerification, error) {
	checksums, err := d.GetWordPressChecksums(version)
	if err != nil {
		return nil, err
	}

	var results []FileVerification

	for relPath, expectedHash := range checksums {
		fullPath := filepath.Join(path, relPath)
		
		verification := FileVerification{
			FilePath:     fullPath,
			ExpectedHash: expectedHash,
			IsCore:       true,
		}

		// Calculate actual hash
		if hash, err := d.calculateMD5(fullPath); err == nil {
			verification.ActualHash = hash
			verification.IsModified = hash != expectedHash
		} else {
			verification.IsModified = true // File missing or unreadable
		}

		// Only report modified files
		if verification.IsModified {
			results = append(results, verification)
		}
	}

	return results, nil
}

// IsCoreFile checks if a file is a known core file for the detected CMS
func (d *Detector) IsCoreFile(cmsInfo CMSInfo, filePath string) bool {
	relPath, err := filepath.Rel(cmsInfo.Path, filePath)
	if err != nil {
		return false
	}

	switch cmsInfo.Type {
	case CMSWordPress:
		return d.isWordPressCoreFile(relPath)
	case CMSJoomla:
		return d.isJoomlaCoreFile(relPath)
	case CMSDrupal:
		return d.isDrupalCoreFile(relPath)
	default:
		return false
	}
}

// isWordPressCoreFile checks if the file is a WordPress core file
func (d *Detector) isWordPressCoreFile(relPath string) bool {
	coreDirs := []string{
		"wp-admin",
		"wp-includes",
	}

	coreFiles := []string{
		"index.php",
		"wp-activate.php",
		"wp-blog-header.php",
		"wp-comments-post.php",
		"wp-config-sample.php",
		"wp-cron.php",
		"wp-links-opml.php",
		"wp-load.php",
		"wp-login.php",
		"wp-mail.php",
		"wp-settings.php",
		"wp-signup.php",
		"wp-trackback.php",
		"xmlrpc.php",
	}

	// Check directories
	for _, dir := range coreDirs {
		if strings.HasPrefix(relPath, dir+string(os.PathSeparator)) || relPath == dir {
			return true
		}
	}

	// Check root files
	for _, file := range coreFiles {
		if relPath == file {
			return true
		}
	}

	return false
}

// isJoomlaCoreFile checks if the file is a Joomla core file
func (d *Detector) isJoomlaCoreFile(relPath string) bool {
	coreDirs := []string{
		"administrator/components",
		"administrator/includes",
		"administrator/language",
		"administrator/modules",
		"includes",
		"language",
		"libraries",
	}

	for _, dir := range coreDirs {
		if strings.HasPrefix(relPath, dir) {
			return true
		}
	}

	return false
}

// isDrupalCoreFile checks if the file is a Drupal core file
func (d *Detector) isDrupalCoreFile(relPath string) bool {
	return strings.HasPrefix(relPath, "core"+string(os.PathSeparator))
}

// calculateMD5 calculates the MD5 hash of a file
func (d *Detector) calculateMD5(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Helper functions
func extractXMLVersion(content string) string {
	// Simple XML version extraction
	if idx := strings.Index(content, "<version>"); idx != -1 {
		end := strings.Index(content[idx:], "</version>")
		if end != -1 {
			return content[idx+9 : idx+end]
		}
	}
	return ""
}

func extractJoomlaVersion(content string) string {
	// Extract Joomla version from Version.php
	var major, minor, patch string

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "MAJOR_VERSION") && strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				major = strings.TrimSpace(strings.Trim(parts[1], ";"))
			}
		}
		if strings.Contains(line, "MINOR_VERSION") && strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				minor = strings.TrimSpace(strings.Trim(parts[1], ";"))
			}
		}
		if strings.Contains(line, "PATCH_VERSION") && strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				patch = strings.TrimSpace(strings.Trim(parts[1], ";"))
			}
		}
	}

	if major != "" {
		return fmt.Sprintf("%s.%s.%s", major, minor, patch)
	}
	return ""
}
