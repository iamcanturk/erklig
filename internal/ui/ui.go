/*
Package ui provides terminal UI components for ERKLIG.
*/
package ui

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
	"github.com/iamcanturk/erklig/internal/scanner"
)

var (
	cyan    = color.New(color.FgCyan, color.Bold)
	red     = color.New(color.FgRed, color.Bold)
	green   = color.New(color.FgGreen, color.Bold)
	yellow  = color.New(color.FgYellow, color.Bold)
	magenta = color.New(color.FgMagenta, color.Bold)
	dim     = color.New(color.Faint)
)

// PrintHeader prints the ERKLIG ASCII art header
func PrintHeader(version, codename string) {
	cyan.Println(`
  ███████╗██████╗ ██╗  ██╗██╗     ██╗ ██████╗ 
  ██╔════╝██╔══██╗██║ ██╔╝██║     ██║██╔════╝ 
  █████╗  ██████╔╝█████╔╝ ██║     ██║██║  ███╗
  ██╔══╝  ██╔══██╗██╔═██╗ ██║     ██║██║   ██║
  ███████╗██║  ██║██║  ██╗███████╗██║╚██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ 
`)
	magenta.Printf("  ⚔️  ERKLIG BACKDOOR ANALYSIS SYSTEM ⚔️\n")
	yellow.Printf("      v%s - %s\n", version, codename)
	dim.Println("      by Can TURK | https://iamcanturk.dev")
	cyan.Println("══════════════════════════════════════════════════════════════")
	fmt.Println()
}

// PrintSuccess prints a success message
func PrintSuccess(msg string) {
	green.Println("╔══════════════════════════════════════════════════════════════╗")
	green.Printf("║  ✓ %s\n", msg)
	green.Println("╚══════════════════════════════════════════════════════════════╝")
}

// PrintAlert prints an alert message
func PrintAlert(msg string) {
	red.Println("╔══════════════════════════════════════════════════════════════╗")
	red.Printf("║  ⚠ ALERT: %s\n", msg)
	red.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// PrintReport prints the final report summary
func PrintReport(findings []scanner.Finding, outputFile string) {
	fmt.Println()
	cyan.Println("╔══════════════════════════════════════════════════════════════╗")
	cyan.Println("║              📊 ANALYSIS COMPLETE                            ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	red.Printf("⚠ CRITICAL: %d file(s) confirmed as threats.\n", len(findings))
	yellow.Printf("Report file: %s.txt\n", outputFile)
	fmt.Println()

	fmt.Println("──────────────────────────────────────────────────────────────")
	fmt.Println("THREAT LIST:")
	for _, f := range findings {
		riskColor := red
		if f.RiskLevel == "HIGH" {
			riskColor = yellow
		} else if f.RiskLevel == "MEDIUM" {
			riskColor = color.New(color.FgYellow)
		}
		riskColor.Printf("  [%s] ", f.RiskLevel)
		fmt.Println(f.FilePath)
	}
	fmt.Println("──────────────────────────────────────────────────────────────")
	fmt.Println()

	yellow.Println("RECOMMENDED CLEANUP COMMAND:")
	dim.Println("(Review the files before executing!)")
	fmt.Println()
	cyan.Printf("  xargs rm -i < %s.txt\n", outputFile)
	fmt.Println()
	fmt.Println("──────────────────────────────────────────────────────────────")
	dim.Println("Thank you for using ERKLIG! - https://github.com/iamcanturk/erklig")
	fmt.Println()
}

// InteractiveAnalysis provides interactive file review
func InteractiveAnalysis(findings []scanner.Finding) []scanner.Finding {
	var confirmed []scanner.Finding
	reader := bufio.NewReader(os.Stdin)

	for i, finding := range findings {
		clearScreen()
		PrintHeader("2.0.0", "Mighty Engine")

		// Progress
		yellow.Printf(">> ANALYZING FILE [%d / %d]\n", i+1, len(findings))
		
		// File info
		cyan.Print("FILE PATH: ")
		fmt.Println(finding.FilePath)
		
		dim.Printf("Size: %d bytes | Modified: %s | Perms: %s | Entropy: %.2f\n",
			finding.FileSize,
			finding.ModTime.Format("2006-01-02 15:04:05"),
			finding.Permissions,
			finding.Entropy,
		)
		
		// Risk level
		riskColor := red
		switch finding.RiskLevel {
		case "HIGH":
			riskColor = yellow
		case "MEDIUM":
			riskColor = color.New(color.FgYellow)
		}
		riskColor.Printf("RISK LEVEL: %s\n", finding.RiskLevel)
		
		fmt.Println("──────────────────────────────────────────────────────────────")
		
		// Show matches
		red.Println(">> DETECTED SUSPICIOUS CODE PATTERNS:")
		maxMatches := 8
		if len(finding.Matches) < maxMatches {
			maxMatches = len(finding.Matches)
		}
		for j := 0; j < maxMatches; j++ {
			m := finding.Matches[j]
			dim.Printf("Line %d: ", m.LineNumber)
			red.Printf("[%s] ", m.Pattern)
			fmt.Println(truncate(m.Line, 80))
		}
		if len(finding.Matches) > maxMatches {
			dim.Printf("...(+%d more matches hidden)...\n", len(finding.Matches)-maxMatches)
		}
		
		fmt.Println("──────────────────────────────────────────────────────────────")
		fmt.Println("COMMAND PANEL:")
		fmt.Printf("  [%sT%s]hreat  -> Mark as THREAT (Add to report)\n", "\033[31m", "\033[0m")
		fmt.Printf("  [%sS%s]afe    -> Mark as SAFE (Skip)\n", "\033[32m", "\033[0m")
		fmt.Printf("  [%sV%s]iew    -> View full source code\n", "\033[34m", "\033[0m")
		fmt.Printf("  [%sQ%s]uit    -> Exit analysis\n", "\033[33m", "\033[0m")
		fmt.Println("──────────────────────────────────────────────────────────────")
		
		for {
			fmt.Print("Enter command (t/s/v/q): ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))
			
			switch input {
			case "t":
				confirmed = append(confirmed, finding)
				red.Println(">> File added to threat report.")
				goto nextFile
			case "s":
				green.Println(">> File marked as safe.")
				goto nextFile
			case "v":
				viewFile(finding.FilePath)
			case "q":
				yellow.Println(">> Analysis interrupted by user.")
				return confirmed
			default:
				red.Println("Invalid command. Please try again.")
			}
		}
	nextFile:
	}

	return confirmed
}

// clearScreen clears the terminal screen
func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// viewFile opens a file in a viewer
func viewFile(path string) {
	// Try bat first, then less
	viewers := []string{"bat", "batcat", "less"}
	for _, v := range viewers {
		if _, err := exec.LookPath(v); err == nil {
			cmd := exec.Command(v, path)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			return
		}
	}
	
	// Fallback: print file content
	content, err := os.ReadFile(path)
	if err != nil {
		red.Printf("Error reading file: %v\n", err)
		return
	}
	fmt.Println(string(content))
}

// truncate truncates a string to maxLen
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
