/*
Package scanner provides the core scanning functionality for ERKLIG.
*/
package scanner

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

// Finding represents a detected threat
type Finding struct {
	FilePath     string    `json:"file_path"`
	FileName     string    `json:"file_name"`
	FileSize     int64     `json:"file_size"`
	ModTime      time.Time `json:"mod_time"`
	Permissions  string    `json:"permissions"`
	Matches      []Match   `json:"matches"`
	Entropy      float64   `json:"entropy"`
	RiskLevel    string    `json:"risk_level"`
	DetectedBy   []string  `json:"detected_by"`
}

// Match represents a pattern match in a file
type Match struct {
	Pattern    string `json:"pattern"`
	LineNumber int    `json:"line_number"`
	Line       string `json:"line"`
	Category   string `json:"category"`
}

// Config holds scanner configuration
type Config struct {
	TargetDir   string
	Days        int
	Verbose     bool
	Interactive bool
}

// Scanner is the main scanning engine
type Scanner struct {
	config     Config
	signatures []Signature
	whitelist  []string
	extensions []string
}

// Signature represents a malware signature pattern
type Signature struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Category string `yaml:"category"`
	Severity string `yaml:"severity"`
	regex    *regexp.Regexp
}

// Default signatures
var defaultSignatures = []Signature{
	// Command Execution
	{Name: "shell_exec", Pattern: `shell_exec\s*\(`, Category: "Command Execution", Severity: "critical"},
	{Name: "passthru", Pattern: `passthru\s*\(`, Category: "Command Execution", Severity: "critical"},
	{Name: "system", Pattern: `\bsystem\s*\(`, Category: "Command Execution", Severity: "critical"},
	{Name: "exec", Pattern: `\bexec\s*\(`, Category: "Command Execution", Severity: "high"},
	{Name: "popen", Pattern: `popen\s*\(`, Category: "Command Execution", Severity: "critical"},
	{Name: "proc_open", Pattern: `proc_open\s*\(`, Category: "Command Execution", Severity: "critical"},
	{Name: "pcntl_exec", Pattern: `pcntl_exec\s*\(`, Category: "Command Execution", Severity: "critical"},
	{Name: "backtick", Pattern: "`[^`]+`", Category: "Command Execution", Severity: "high"},

	// Code Evaluation
	{Name: "eval", Pattern: `\beval\s*\(`, Category: "Code Evaluation", Severity: "critical"},
	{Name: "assert", Pattern: `\bassert\s*\(`, Category: "Code Evaluation", Severity: "high"},
	{Name: "create_function", Pattern: `create_function\s*\(`, Category: "Code Evaluation", Severity: "high"},
	{Name: "preg_replace_e", Pattern: `preg_replace\s*\([^)]*['"]/.*/e`, Category: "Code Evaluation", Severity: "critical"},
	{Name: "call_user_func", Pattern: `call_user_func\s*\(`, Category: "Code Evaluation", Severity: "medium"},

	// Encoding/Obfuscation
	{Name: "base64_decode", Pattern: `base64_decode\s*\(`, Category: "Obfuscation", Severity: "medium"},
	{Name: "gzinflate", Pattern: `gzinflate\s*\(`, Category: "Obfuscation", Severity: "high"},
	{Name: "gzuncompress", Pattern: `gzuncompress\s*\(`, Category: "Obfuscation", Severity: "high"},
	{Name: "str_rot13", Pattern: `str_rot13\s*\(`, Category: "Obfuscation", Severity: "medium"},
	{Name: "convert_uudecode", Pattern: `convert_uudecode\s*\(`, Category: "Obfuscation", Severity: "high"},
	{Name: "hex2bin", Pattern: `hex2bin\s*\(`, Category: "Obfuscation", Severity: "low"},

	// Known Webshells
	{Name: "FilesMan", Pattern: `FilesMan`, Category: "Known Webshell", Severity: "critical"},
	{Name: "WSO", Pattern: `wso_version|WSO\s+\d`, Category: "Known Webshell", Severity: "critical"},
	{Name: "c99shell", Pattern: `c99shell|c99_buff_prepare`, Category: "Known Webshell", Severity: "critical"},
	{Name: "r57shell", Pattern: `r57shell|r57_get_perms`, Category: "Known Webshell", Severity: "critical"},
	{Name: "b374k", Pattern: `b374k|b374k\s+shell`, Category: "Known Webshell", Severity: "critical"},
	{Name: "weevely", Pattern: `weevely`, Category: "Known Webshell", Severity: "critical"},

	// Network Functions
	{Name: "fsockopen", Pattern: `fsockopen\s*\(`, Category: "Network", Severity: "medium"},
	{Name: "socket_accept", Pattern: `socket_accept\s*\(`, Category: "Network", Severity: "high"},
	{Name: "curl_exec", Pattern: `curl_exec\s*\(`, Category: "Network", Severity: "low"},
	{Name: "file_get_contents_url", Pattern: `file_get_contents\s*\(\s*['"]https?://`, Category: "Network", Severity: "medium"},

	// Filesystem Abuse
	{Name: "symlink", Pattern: `\bsymlink\s*\(`, Category: "Filesystem", Severity: "high"},
	{Name: "chmod_777", Pattern: `chmod\s*\([^)]*777`, Category: "Filesystem", Severity: "high"},
	{Name: "move_uploaded_file", Pattern: `move_uploaded_file\s*\(`, Category: "Filesystem", Severity: "medium"},

	// Suspicious Patterns
	{Name: "hidden_input", Pattern: `\$_(?:POST|GET|REQUEST|COOKIE)\s*\[\s*['"][^'"]+['"]\s*\]\s*\(`, Category: "Suspicious", Severity: "critical"},
	{Name: "variable_function", Pattern: `\$[a-zA-Z_]+\s*\(`, Category: "Suspicious", Severity: "medium"},
	{Name: "short_open_tag_eval", Pattern: `<\?=\s*\$_`, Category: "Suspicious", Severity: "high"},
}

// Default whitelist directories
var defaultWhitelist = []string{
	"vendor",
	"node_modules",
	".git",
	"wp-includes",
	"wp-admin",
	"libraries",
	"core",
	"framework",
	"cache",
	"logs",
}

// Scannable file extensions
var defaultExtensions = []string{
	".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".inc",
	".asp", ".aspx", ".ascx", ".ashx",
	".jsp", ".jspx",
	".js",
	".py", ".pl", ".cgi", ".rb",
}

// New creates a new Scanner instance
func New(cfg Config) *Scanner {
	s := &Scanner{
		config:     cfg,
		signatures: defaultSignatures,
		whitelist:  defaultWhitelist,
		extensions: defaultExtensions,
	}

	// Compile regex patterns
	for i := range s.signatures {
		s.signatures[i].regex = regexp.MustCompile(s.signatures[i].Pattern)
	}

	return s
}

// Scan performs the security scan
func (s *Scanner) Scan() ([]Finding, error) {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Collect files to scan
	var files []string
	err := filepath.Walk(s.config.TargetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}

		// Skip directories
		if info.IsDir() {
			// Check whitelist
			for _, w := range s.whitelist {
				if strings.Contains(path, string(os.PathSeparator)+w+string(os.PathSeparator)) ||
					strings.HasSuffix(path, string(os.PathSeparator)+w) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check extension
		ext := strings.ToLower(filepath.Ext(path))
		validExt := false
		for _, e := range s.extensions {
			if ext == e {
				validExt = true
				break
			}
		}
		if !validExt {
			return nil
		}

		// Check modification time if days filter is set
		if s.config.Days > 0 {
			cutoff := time.Now().AddDate(0, 0, -s.config.Days)
			if info.ModTime().Before(cutoff) {
				return nil
			}
		}

		files = append(files, path)
		return nil
	})

	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return findings, nil
	}

	// Create progress bar
	bar := progressbar.NewOptions(len(files),
		progressbar.OptionSetDescription("[SCANNING]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerPadding: "░",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowCount(),
		progressbar.OptionShowElapsedTimeOnFinish(),
	)

	// Scan files concurrently
	semaphore := make(chan struct{}, 10) // Limit concurrent goroutines

	for _, file := range files {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire

		go func(filePath string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release

			if finding := s.scanFile(filePath); finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
			}
			bar.Add(1)
		}(file)
	}

	wg.Wait()
	bar.Finish()

	return findings, nil
}

// scanFile scans a single file for threats
func (s *Scanner) scanFile(filePath string) *Finding {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil
	}

	var matches []Match
	var detectedBy []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, sig := range s.signatures {
			if sig.regex.MatchString(line) {
				matches = append(matches, Match{
					Pattern:    sig.Name,
					LineNumber: lineNum,
					Line:       truncateLine(line, 200),
					Category:   sig.Category,
				})

				// Track unique detection methods
				found := false
				for _, d := range detectedBy {
					if d == sig.Category {
						found = true
						break
					}
				}
				if !found {
					detectedBy = append(detectedBy, sig.Category)
				}
			}
		}
	}

	if len(matches) == 0 {
		return nil
	}

	// Calculate entropy
	file.Seek(0, 0)
	entropy := calculateEntropy(file)

	// Determine risk level
	riskLevel := determineRiskLevel(matches, entropy)

	return &Finding{
		FilePath:    filePath,
		FileName:    filepath.Base(filePath),
		FileSize:    info.Size(),
		ModTime:     info.ModTime(),
		Permissions: info.Mode().String(),
		Matches:     matches,
		Entropy:     entropy,
		RiskLevel:   riskLevel,
		DetectedBy:  detectedBy,
	}
}

// calculateEntropy calculates Shannon entropy of file content
func calculateEntropy(file *os.File) float64 {
	bytes := make([]byte, 4096)
	n, err := file.Read(bytes)
	if err != nil || n == 0 {
		return 0
	}
	bytes = bytes[:n]

	// Count byte frequencies
	freq := make(map[byte]int)
	for _, b := range bytes {
		freq[b]++
	}

	// Calculate entropy
	var entropy float64
	total := float64(len(bytes))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// determineRiskLevel determines the risk level based on findings
func determineRiskLevel(matches []Match, entropy float64) string {
	criticalCount := 0
	highCount := 0

	for _, m := range matches {
		// Check signature severity
		for _, sig := range defaultSignatures {
			if sig.Name == m.Pattern {
				switch sig.Severity {
				case "critical":
					criticalCount++
				case "high":
					highCount++
				}
			}
		}
	}

	// High entropy indicates obfuscation
	if entropy > 7.0 {
		return "CRITICAL"
	}

	if criticalCount > 0 {
		return "CRITICAL"
	}
	if highCount > 0 || entropy > 6.0 {
		return "HIGH"
	}
	if len(matches) > 3 {
		return "HIGH"
	}
	return "MEDIUM"
}

// truncateLine truncates a line to maxLen characters
func truncateLine(line string, maxLen int) string {
	if len(line) <= maxLen {
		return line
	}
	return line[:maxLen] + "..."
}
