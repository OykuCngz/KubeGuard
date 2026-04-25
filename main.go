package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/user/kubeguard/pkg/scanner"
)

var rootCmd = &cobra.Command{
	Use:   "kubeguard",
	Short: "KubeGuard is a CLI tool to audit Kubernetes clusters for best practices",
	Long: `KubeGuard scans your Kubernetes cluster for missing labels, 
resource limits, and security misconfigurations. 
Built for Google-scale infrastructure auditing.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Welcome to KubeGuard! Use 'kubeguard audit' to start scanning.")
	},
}

var (
	namespace string
	jsonOut   bool
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit the current Kubernetes cluster",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔍 Auditing cluster...")
		scanner.RunAudit(namespace, jsonOut)
	},
}

func main() {
	auditCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Specific namespace to audit (default: all)")
	auditCmd.Flags().BoolVarP(&jsonOut, "json", "j", false, "Output results in JSON format")
	
	rootCmd.AddCommand(auditCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
