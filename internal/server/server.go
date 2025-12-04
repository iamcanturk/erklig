/*
Package server provides the web dashboard functionality for ERKLIG.
*/
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/websocket/v2"
	"github.com/iamcanturk/erklig/internal/scanner"
)

//go:embed static/*
var staticFiles embed.FS

// ScanStatus represents the current scan status
type ScanStatus struct {
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	Status      string    `json:"status"` // pending, scanning, completed, error
	Progress    int       `json:"progress"`
	TotalFiles  int       `json:"total_files"`
	ScannedFiles int      `json:"scanned_files"`
	Threats     int       `json:"threats"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time,omitempty"`
	Message     string    `json:"message,omitempty"`
}

// ScanResult represents a complete scan result
type ScanResult struct {
	ScanStatus
	Findings []Finding `json:"findings"`
}

// Finding represents a detected threat (simplified for dashboard)
type Finding struct {
	FilePath    string          `json:"file_path"`
	FileName    string          `json:"file_name"`
	FileSize    int64           `json:"file_size"`
	ModTime     string          `json:"mod_time"`
	RiskLevel   string          `json:"risk_level"`
	Matches     []scanner.Match `json:"matches"`
	Categories  []string        `json:"categories"`
}

// Server represents the dashboard server
type Server struct {
	app           *fiber.App
	port          int
	scans         map[string]*ScanStatus
	results       map[string]*ScanResult
	clients       map[*websocket.Conn]bool
	quarantineDir string
	mu            sync.RWMutex
}

// NewServer creates a new dashboard server
func NewServer(port int) *Server {
	// Create quarantine directory
	quarantineDir := filepath.Join(os.TempDir(), "erklig_quarantine")
	os.MkdirAll(quarantineDir, 0755)

	s := &Server{
		port:          port,
		scans:         make(map[string]*ScanStatus),
		results:       make(map[string]*ScanResult),
		clients:       make(map[*websocket.Conn]bool),
		quarantineDir: quarantineDir,
	}

	s.setupRoutes()
	return s
}

// setupRoutes configures the HTTP routes
func (s *Server) setupRoutes() {
	s.app = fiber.New(fiber.Config{
		AppName: "ERKLIG Dashboard",
	})

	// CORS for development
	s.app.Use(cors.New())

	// API routes
	api := s.app.Group("/api")
	
	// Scan endpoints
	api.Post("/scan", s.handleStartScan)
	api.Get("/scan/:id", s.handleGetScan)
	api.Get("/scans", s.handleListScans)
	api.Delete("/scan/:id", s.handleDeleteScan)
	
	// Report endpoints
	api.Get("/report/:id", s.handleGetReport)
	api.Get("/report/:id/download", s.handleDownloadReport)
	
	// File action endpoints
	api.Get("/file/view", s.handleViewFile)
	api.Post("/file/quarantine", s.handleQuarantineFile)
	api.Post("/file/delete", s.handleDeleteFile)
	api.Post("/file/restore", s.handleRestoreFile)
	
	// System info
	api.Get("/info", s.handleSystemInfo)

	// WebSocket for real-time updates
	s.app.Use("/ws", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			c.Locals("allowed", true)
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})
	s.app.Get("/ws", websocket.New(s.handleWebSocket))

	// Static files (dashboard UI)
	s.app.Use("/", filesystem.New(filesystem.Config{
		Root:       http.FS(staticFiles),
		PathPrefix: "static",
		Index:      "index.html",
	}))
}

// Start starts the dashboard server
func (s *Server) Start() error {
	fmt.Printf("\n🌐 ERKLIG Dashboard running at http://localhost:%d\n", s.port)
	fmt.Printf("   Press Ctrl+C to stop\n\n")
	return s.app.Listen(fmt.Sprintf(":%d", s.port))
}

// Stop stops the dashboard server
func (s *Server) Stop() error {
	return s.app.Shutdown()
}

// handleStartScan starts a new scan
func (s *Server) handleStartScan(c *fiber.Ctx) error {
	var req struct {
		Target string `json:"target"`
		Days   int    `json:"days"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.Target == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Target directory is required"})
	}

	// Generate scan ID
	scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())

	// Create scan status
	status := &ScanStatus{
		ID:        scanID,
		Target:    req.Target,
		Status:    "pending",
		StartTime: time.Now(),
	}

	s.mu.Lock()
	s.scans[scanID] = status
	s.mu.Unlock()

	// Start scan in background
	go s.runScan(scanID, req.Target, req.Days)

	return c.JSON(status)
}

// handleGetScan returns the status of a specific scan
func (s *Server) handleGetScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	s.mu.RLock()
	status, exists := s.scans[scanID]
	s.mu.RUnlock()

	if !exists {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	return c.JSON(status)
}

// handleListScans returns all scans
func (s *Server) handleListScans(c *fiber.Ctx) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scans := make([]*ScanStatus, 0, len(s.scans))
	for _, scan := range s.scans {
		scans = append(scans, scan)
	}

	return c.JSON(scans)
}

// handleDeleteScan deletes a scan
func (s *Server) handleDeleteScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	s.mu.Lock()
	delete(s.scans, scanID)
	delete(s.results, scanID)
	s.mu.Unlock()

	return c.JSON(fiber.Map{"message": "Scan deleted"})
}

// handleGetReport returns the full report for a scan
func (s *Server) handleGetReport(c *fiber.Ctx) error {
	scanID := c.Params("id")

	s.mu.RLock()
	result, exists := s.results[scanID]
	s.mu.RUnlock()

	if !exists {
		return c.Status(404).JSON(fiber.Map{"error": "Report not found"})
	}

	return c.JSON(result)
}

// handleDownloadReport returns the report as a downloadable file
func (s *Server) handleDownloadReport(c *fiber.Ctx) error {
	scanID := c.Params("id")
	format := c.Query("format", "json")

	s.mu.RLock()
	result, exists := s.results[scanID]
	s.mu.RUnlock()

	if !exists {
		return c.Status(404).JSON(fiber.Map{"error": "Report not found"})
	}

	switch format {
	case "json":
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=erklig_report_%s.json", scanID))
		return c.JSON(result)
	default:
		return c.Status(400).JSON(fiber.Map{"error": "Invalid format"})
	}
}

// handleSystemInfo returns system information
func (s *Server) handleSystemInfo(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"version":     "2.0.0",
		"name":        "ERKLIG",
		"description": "Mighty Backdoor Analysis Engine",
		"author":      "Can TÜRK",
		"website":     "https://iamcanturk.dev",
	})
}

// handleWebSocket handles WebSocket connections for real-time updates
func (s *Server) handleWebSocket(c *websocket.Conn) {
	// Register client
	s.mu.Lock()
	s.clients[c] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, c)
		s.mu.Unlock()
		c.Close()
	}()

	// Keep connection alive and handle messages
	for {
		_, _, err := c.ReadMessage()
		if err != nil {
			break
		}
	}
}

// broadcastUpdate sends an update to all connected WebSocket clients
func (s *Server) broadcastUpdate(event string, data interface{}) {
	message := map[string]interface{}{
		"event": event,
		"data":  data,
		"time":  time.Now().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(message)
	if err != nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		client.WriteMessage(websocket.TextMessage, jsonData)
	}
}

// handleViewFile returns the content of a file
func (s *Server) handleViewFile(c *fiber.Ctx) error {
	filePath := c.Query("path")
	if filePath == "" {
		return c.Status(400).JSON(fiber.Map{"error": "File path is required"})
	}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": fmt.Sprintf("Could not read file: %v", err)})
	}

	// Get file info
	info, _ := os.Stat(filePath)

	return c.JSON(fiber.Map{
		"path":     filePath,
		"content":  string(content),
		"size":     info.Size(),
		"mod_time": info.ModTime().Format("2006-01-02 15:04:05"),
	})
}

// handleQuarantineFile moves a file to quarantine
func (s *Server) handleQuarantineFile(c *fiber.Ctx) error {
	var req struct {
		FilePath string `json:"file_path"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.FilePath == "" {
		return c.Status(400).JSON(fiber.Map{"error": "File path is required"})
	}

	// Check if file exists
	if _, err := os.Stat(req.FilePath); os.IsNotExist(err) {
		return c.Status(404).JSON(fiber.Map{"error": "File not found"})
	}

	// Create quarantine subdirectory with timestamp
	timestamp := time.Now().Format("20060102_150405")
	quarantinePath := filepath.Join(s.quarantineDir, timestamp)
	os.MkdirAll(quarantinePath, 0755)

	// Move file to quarantine
	fileName := filepath.Base(req.FilePath)
	newPath := filepath.Join(quarantinePath, fileName)

	// Save original path metadata
	metaPath := filepath.Join(quarantinePath, fileName+".meta")
	os.WriteFile(metaPath, []byte(req.FilePath), 0644)

	// Move the file
	if err := os.Rename(req.FilePath, newPath); err != nil {
		// If rename fails (cross-device), try copy and delete
		content, err := os.ReadFile(req.FilePath)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": fmt.Sprintf("Could not read file: %v", err)})
		}
		if err := os.WriteFile(newPath, content, 0644); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": fmt.Sprintf("Could not write to quarantine: %v", err)})
		}
		os.Remove(req.FilePath)
	}

	s.broadcastUpdate("file_quarantined", fiber.Map{
		"original_path":   req.FilePath,
		"quarantine_path": newPath,
	})

	return c.JSON(fiber.Map{
		"message":         "File quarantined successfully",
		"quarantine_path": newPath,
	})
}

// handleDeleteFile permanently deletes a file
func (s *Server) handleDeleteFile(c *fiber.Ctx) error {
	var req struct {
		FilePath string `json:"file_path"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.FilePath == "" {
		return c.Status(400).JSON(fiber.Map{"error": "File path is required"})
	}

	// Check if file exists
	if _, err := os.Stat(req.FilePath); os.IsNotExist(err) {
		return c.Status(404).JSON(fiber.Map{"error": "File not found"})
	}

	// Delete the file
	if err := os.Remove(req.FilePath); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": fmt.Sprintf("Could not delete file: %v", err)})
	}

	s.broadcastUpdate("file_deleted", fiber.Map{
		"file_path": req.FilePath,
	})

	return c.JSON(fiber.Map{"message": "File deleted successfully"})
}

// handleRestoreFile restores a file from quarantine
func (s *Server) handleRestoreFile(c *fiber.Ctx) error {
	var req struct {
		QuarantinePath string `json:"quarantine_path"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.QuarantinePath == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Quarantine path is required"})
	}

	// Read original path from metadata
	metaPath := req.QuarantinePath + ".meta"
	originalPathBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Could not find original path metadata"})
	}
	originalPath := string(originalPathBytes)

	// Read quarantined file
	content, err := os.ReadFile(req.QuarantinePath)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Quarantined file not found"})
	}

	// Restore to original location
	if err := os.WriteFile(originalPath, content, 0644); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": fmt.Sprintf("Could not restore file: %v", err)})
	}

	// Remove from quarantine
	os.Remove(req.QuarantinePath)
	os.Remove(metaPath)

	s.broadcastUpdate("file_restored", fiber.Map{
		"original_path":   originalPath,
		"quarantine_path": req.QuarantinePath,
	})

	return c.JSON(fiber.Map{
		"message":       "File restored successfully",
		"original_path": originalPath,
	})
}

// runScan executes the actual scan with real scanner integration
func (s *Server) runScan(scanID, target string, days int) {
	s.mu.Lock()
	status := s.scans[scanID]
	status.Status = "scanning"
	s.mu.Unlock()

	s.broadcastUpdate("scan_started", status)

	// Resolve absolute path
	absPath, err := filepath.Abs(target)
	if err != nil {
		s.updateScanError(scanID, fmt.Sprintf("Invalid path: %v", err))
		return
	}

	// Check if directory exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		s.updateScanError(scanID, fmt.Sprintf("Directory not found: %s", absPath))
		return
	}

	// Create scanner configuration
	cfg := scanner.Config{
		TargetDir:   absPath,
		Days:        days,
		Verbose:     false,
		Interactive: false,
	}

	// Initialize scanner with progress callback
	sc := scanner.New(cfg)
	
	// Run the scan
	findings, err := sc.Scan()
	if err != nil {
		s.updateScanError(scanID, fmt.Sprintf("Scan failed: %v", err))
		return
	}

	// Convert scanner findings to server findings
	serverFindings := make([]Finding, 0, len(findings))
	for _, f := range findings {
		categories := make([]string, 0)
		categoryMap := make(map[string]bool)

		for _, m := range f.Matches {
			if !categoryMap[m.Category] {
				categories = append(categories, m.Category)
				categoryMap[m.Category] = true
			}
		}

		serverFindings = append(serverFindings, Finding{
			FilePath:   f.FilePath,
			FileName:   f.FileName,
			FileSize:   f.FileSize,
			ModTime:    f.ModTime.Format("2006-01-02 15:04:05"),
			RiskLevel:  f.RiskLevel,
			Matches:    f.Matches,
			Categories: categories,
		})
	}

	// Update status
	s.mu.Lock()
	status.Status = "completed"
	status.EndTime = time.Now()
	status.Threats = len(serverFindings)
	status.Progress = 100

	// Create result
	result := &ScanResult{
		ScanStatus: *status,
		Findings:   serverFindings,
	}
	s.results[scanID] = result
	s.mu.Unlock()

	s.broadcastUpdate("scan_completed", result)
}

// updateScanError updates scan status with error
func (s *Server) updateScanError(scanID, message string) {
	s.mu.Lock()
	if status, exists := s.scans[scanID]; exists {
		status.Status = "error"
		status.Message = message
		status.EndTime = time.Now()
	}
	s.mu.Unlock()

	s.broadcastUpdate("scan_error", map[string]string{
		"id":      scanID,
		"message": message,
	})
}
