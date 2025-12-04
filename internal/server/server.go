/*
Package server provides the web dashboard functionality for ERKLIG.
*/
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/websocket/v2"
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
	FilePath    string   `json:"file_path"`
	FileName    string   `json:"file_name"`
	FileSize    int64    `json:"file_size"`
	ModTime     string   `json:"mod_time"`
	RiskLevel   string   `json:"risk_level"`
	Matches     []string `json:"matches"`
	Categories  []string `json:"categories"`
}

// Server represents the dashboard server
type Server struct {
	app     *fiber.App
	port    int
	scans   map[string]*ScanStatus
	results map[string]*ScanResult
	clients map[*websocket.Conn]bool
	mu      sync.RWMutex
}

// NewServer creates a new dashboard server
func NewServer(port int) *Server {
	s := &Server{
		port:    port,
		scans:   make(map[string]*ScanStatus),
		results: make(map[string]*ScanResult),
		clients: make(map[*websocket.Conn]bool),
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

// runScan executes the actual scan (placeholder - will integrate with scanner)
func (s *Server) runScan(scanID, target string, days int) {
	s.mu.Lock()
	status := s.scans[scanID]
	status.Status = "scanning"
	s.mu.Unlock()

	s.broadcastUpdate("scan_started", status)

	// TODO: Integrate with actual scanner
	// For now, simulate scanning
	time.Sleep(2 * time.Second)

	s.mu.Lock()
	status.Status = "completed"
	status.EndTime = time.Now()
	status.TotalFiles = 100
	status.ScannedFiles = 100
	status.Progress = 100
	
	// Create result
	result := &ScanResult{
		ScanStatus: *status,
		Findings:   []Finding{},
	}
	s.results[scanID] = result
	s.mu.Unlock()

	s.broadcastUpdate("scan_completed", result)
}
