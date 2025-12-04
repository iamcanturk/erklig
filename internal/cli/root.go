/*
Package cli provides the command-line interface for ERKLIG.
*/
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/fatih/color"
	"github.com/iamcanturk/erklig/internal/scanner"
	"github.com/iamcanturk/erklig/internal/ui"
	"github.com/spf13/cobra"
)

var (
	// Version information
	Version   = "2.0.0"
	Codename  = "Mighty Engine"
	BuildDate = "unknown"

	// Flags
	targetDir    string
	outputFile   string
	configFile   string
	days         int
	verbose      bool
	noInteract   bool
	jsonOutput   bool
	htmlOutput   bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "erklig [directory]",
	Short: "⚔️ ERKLIG - Mighty Backdoor Analysis Engine",
	Long: `
  ███████╗██████╗ ██╗  ██╗██╗     ██╗ ██████╗ 
  ██╔════╝██╔══██╗██║ ██╔╝██║     ██║██╔════╝ 
  █████╗  ██████╔╝█████╔╝ ██║     ██║██║  ███╗
  ██╔══╝  ██╔══██╗██╔═██╗ ██║     ██║██║   ██║
  ███████╗██║  ██║██║  ██╗███████╗██║╚██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ 

ERKLIG is a powerful, open-source security tool for detecting
backdoors, web shells, and malicious code in web servers.

Inspired by Erlik Khan, the powerful deity of Turkish mythology.

Examples:
  erklig                    # Scan current directory
  erklig /var/www/html      # Scan specific directory
  erklig --days 30          # Scan files modified in last 30 days
  erklig --json             # Output results as JSON
  erklig --no-interact      # Non-interactive mode (CI/CD friendly)

Author: Can TÜRK <https://iamcanturk.dev>`,
	RunE: runScan,
}

func init() {
	rootCmd.Flags().StringVarP(&targetDir, "target", "t", ".", "Target directory to scan")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "erklig_report", "Output file name (without extension)")
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "Custom configuration file")
	rootCmd.Flags().IntVarP(&days, "days", "d", 0, "Only scan files modified in last N days (0 = all)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVar(&noInteract, "no-interact", false, "Non-interactive mode (for CI/CD)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.Flags().BoolVar(&htmlOutput, "html", false, "Generate HTML report")

	// Add version command
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		cyan := color.New(color.FgCyan, color.Bold)
		cyan.Printf("ERKLIG %s (%s)\n", Version, Codename)
		fmt.Printf("Build Date: %s\n", BuildDate)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

// runScan is the main scanning logic
func runScan(cmd *cobra.Command, args []string) error {
	// Handle positional argument for target directory
	if len(args) > 0 {
		targetDir = args[0]
	}

	// Resolve absolute path
	absPath, err := filepath.Abs(targetDir)
	if err != nil {
		return fmt.Errorf("invalid target directory: %w", err)
	}

	// Check if directory exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %s", absPath)
	}

	// Print header
	ui.PrintHeader(Version, Codename)

	// Create scanner configuration
	cfg := scanner.Config{
		TargetDir:   absPath,
		Days:        days,
		Verbose:     verbose,
		Interactive: !noInteract,
	}

	// Initialize and run scanner
	s := scanner.New(cfg)
	results, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Handle results
	if len(results) == 0 {
		ui.PrintSuccess("System clean. No potential threats detected.")
		return nil
	}

	ui.PrintAlert(fmt.Sprintf("%d potential threat(s) detected.", len(results)))

	// Interactive analysis or direct output
	var confirmedThreats []scanner.Finding
	if !noInteract {
		confirmedThreats = ui.InteractiveAnalysis(results)
	} else {
		confirmedThreats = results
	}

	// Generate reports
	if len(confirmedThreats) > 0 {
		// Text report
		if err := scanner.WriteTextReport(outputFile+".txt", confirmedThreats); err != nil {
			color.Red("Failed to write text report: %v", err)
		}

		// JSON report
		if jsonOutput {
			if err := scanner.WriteJSONReport(outputFile+".json", confirmedThreats); err != nil {
				color.Red("Failed to write JSON report: %v", err)
			}
		}

		// HTML report
		if htmlOutput {
			if err := scanner.WriteHTMLReport(outputFile+".html", confirmedThreats); err != nil {
				color.Red("Failed to write HTML report: %v", err)
			}
		}

		ui.PrintReport(confirmedThreats, outputFile)
	} else {
		ui.PrintSuccess("No threats confirmed after review.")
	}

	return nil
}
