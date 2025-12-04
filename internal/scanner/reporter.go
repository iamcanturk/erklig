package scanner

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"
)

// WriteTextReport writes findings to a text file
func WriteTextReport(filename string, findings []Finding) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, f := range findings {
		fmt.Fprintf(file, "%s\n", f.FilePath)
	}

	return nil
}

// WriteJSONReport writes findings to a JSON file
func WriteJSONReport(filename string, findings []Finding) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	report := struct {
		GeneratedAt string    `json:"generated_at"`
		TotalThreats int      `json:"total_threats"`
		Findings    []Finding `json:"findings"`
	}{
		GeneratedAt:  time.Now().Format(time.RFC3339),
		TotalThreats: len(findings),
		Findings:     findings,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// WriteHTMLReport writes findings to an HTML file
func WriteHTMLReport(filename string, findings []Finding) error {
	const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ERKLIG Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0d1117; 
            color: #c9d1d9; 
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header { 
            text-align: center; 
            padding: 40px 0; 
            border-bottom: 1px solid #30363d;
            margin-bottom: 30px;
        }
        h1 { color: #58a6ff; font-size: 2.5em; margin-bottom: 10px; }
        .subtitle { color: #8b949e; font-size: 1.1em; }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px;
        }
        .stat-card { 
            background: #161b22; 
            padding: 20px; 
            border-radius: 8px; 
            border: 1px solid #30363d;
            text-align: center;
        }
        .stat-card h3 { color: #8b949e; font-size: 0.9em; margin-bottom: 10px; }
        .stat-card .value { font-size: 2em; font-weight: bold; }
        .critical { color: #f85149; }
        .high { color: #f0883e; }
        .medium { color: #d29922; }
        .finding { 
            background: #161b22; 
            border: 1px solid #30363d; 
            border-radius: 8px; 
            margin-bottom: 20px;
            overflow: hidden;
        }
        .finding-header { 
            padding: 15px 20px; 
            background: #21262d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-path { 
            font-family: monospace; 
            font-size: 0.9em;
            color: #58a6ff;
        }
        .risk-badge { 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 0.8em;
            font-weight: bold;
        }
        .risk-CRITICAL { background: #f85149; color: white; }
        .risk-HIGH { background: #f0883e; color: white; }
        .risk-MEDIUM { background: #d29922; color: white; }
        .finding-body { padding: 20px; }
        .meta { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
            gap: 10px;
            margin-bottom: 15px;
            font-size: 0.85em;
            color: #8b949e;
        }
        .matches { margin-top: 15px; }
        .match { 
            background: #0d1117; 
            padding: 10px 15px; 
            margin: 5px 0;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85em;
            overflow-x: auto;
        }
        .match-line { color: #8b949e; }
        .match-pattern { color: #f85149; font-weight: bold; }
        .match-code { color: #c9d1d9; }
        footer { 
            text-align: center; 
            padding: 40px 0; 
            color: #8b949e;
            border-top: 1px solid #30363d;
            margin-top: 30px;
        }
        footer a { color: #58a6ff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>⚔️ ERKLIG Security Report</h1>
            <p class="subtitle">Generated: {{.GeneratedAt}}</p>
        </header>

        <div class="stats">
            <div class="stat-card">
                <h3>Total Threats</h3>
                <div class="value">{{.TotalThreats}}</div>
            </div>
            <div class="stat-card">
                <h3>Critical</h3>
                <div class="value critical">{{.CriticalCount}}</div>
            </div>
            <div class="stat-card">
                <h3>High</h3>
                <div class="value high">{{.HighCount}}</div>
            </div>
            <div class="stat-card">
                <h3>Medium</h3>
                <div class="value medium">{{.MediumCount}}</div>
            </div>
        </div>

        {{range .Findings}}
        <div class="finding">
            <div class="finding-header">
                <span class="finding-path">{{.FilePath}}</span>
                <span class="risk-badge risk-{{.RiskLevel}}">{{.RiskLevel}}</span>
            </div>
            <div class="finding-body">
                <div class="meta">
                    <span>📁 Size: {{.FileSize}} bytes</span>
                    <span>📅 Modified: {{.ModTime.Format "2006-01-02 15:04:05"}}</span>
                    <span>🔐 Perms: {{.Permissions}}</span>
                    <span>📊 Entropy: {{printf "%.2f" .Entropy}}</span>
                </div>
                <div class="matches">
                    {{range .Matches}}
                    <div class="match">
                        <span class="match-line">Line {{.LineNumber}}:</span>
                        <span class="match-pattern">[{{.Pattern}}]</span>
                        <span class="match-code">{{.Line}}</span>
                    </div>
                    {{end}}
                </div>
            </div>
        </div>
        {{end}}

        <footer>
            <p>Generated by <a href="https://github.com/iamcanturk/erklig">ERKLIG</a> - Mighty Backdoor Analysis Engine</p>
            <p>Created by <a href="https://iamcanturk.dev">Can TÜRK</a></p>
        </footer>
    </div>
</body>
</html>`

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Count by risk level
	var criticalCount, highCount, mediumCount int
	for _, f := range findings {
		switch f.RiskLevel {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		}
	}

	data := struct {
		GeneratedAt   string
		TotalThreats  int
		CriticalCount int
		HighCount     int
		MediumCount   int
		Findings      []Finding
	}{
		GeneratedAt:   time.Now().Format("2006-01-02 15:04:05"),
		TotalThreats:  len(findings),
		CriticalCount: criticalCount,
		HighCount:     highCount,
		MediumCount:   mediumCount,
		Findings:      findings,
	}

	return tmpl.Execute(file, data)
}
