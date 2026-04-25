package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"text/tabwriter"

	"github.com/fatih/color"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// AuditIssue represents a single finding in the cluster
type AuditIssue struct {
	Category    string
	Resource    string
	Name        string
	Message     string
	Severity    string // High, Medium, Low
	Remediation string // How to fix it (Google-style)
}

// RunAudit initializes the K8s client and starts the scanning process
func RunAudit(ns string, jsonOut bool) {
	// Setup K8s client
	homeDir, _ := os.UserHomeDir()
	kubeconfig := filepath.Join(homeDir, ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		color.Yellow("💡 No active cluster found. Running in DEMO MODE for Google Portfolio showcase...")
		runDemoMode(jsonOut)
		return
	}

	var issues []AuditIssue
	if !jsonOut {
		color.Cyan("🚀 Connected to cluster. Performing professional audit on namespace: %s", func() string {
			if ns == "" {
				return "all"
			}
			return ns
		}())
	}

	// 1. Audit Pods (Best Practices)
	issues = append(issues, auditPods(clientset, ns)...)

	// 2. Audit Costs (Unused Resources)
	issues = append(issues, auditCosts(clientset)...)

	// 3. Print Results
	if jsonOut {
		renderJSON(issues)
	} else {
		renderTable(issues)
	}
}

func runDemoMode(jsonOut bool) {
	mockIssues := []AuditIssue{
		{Category: "Security", Resource: "Pod", Name: "default/nginx-app", Message: "Privileged container detected", Severity: "High", Remediation: "Set allowPrivilegeEscalation: false in securityContext."},
		{Category: "Efficiency", Resource: "Deployment", Name: "prod/api-server", Message: "No CPU/Memory limits defined", Severity: "High", Remediation: "Add resources.limits to the container spec."},
		{Category: "Cost", Resource: "Service", Name: "staging/db-lb", Message: "Orphaned LoadBalancer", Severity: "Medium", Remediation: "Delete unused cloud LoadBalancer service."},
		{Category: "Best Practice", Resource: "Pod", Name: "kube-system/mon", Message: "Missing health check", Severity: "Low", Remediation: "Add livenessProbe and readinessProbe."},
		{Category: "Cost", Resource: "ReplicaSet", Name: "default/old-rs-1", Message: "Orphaned (0 replicas)", Severity: "Low", Remediation: "Run 'kubectl delete rs' to clean up."},
	}
	if jsonOut {
		renderJSON(mockIssues)
	} else {
		renderTable(mockIssues)
	}
}

func auditPods(clientset *kubernetes.Clientset, ns string) []AuditIssue {
	var issues []AuditIssue
	pods, err := clientset.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		color.Yellow("⚠️ Error listing pods: %v", err)
		return issues
	}

	for _, pod := range pods.Items {
		// Rule: Labels
		if len(pod.Labels) == 0 {
			issues = append(issues, AuditIssue{
				Category:    "Best Practice",
				Resource:    "Pod",
				Name:        fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
				Message:     "Missing mandatory labels",
				Severity:    "Medium",
				Remediation: "Add standard labels like app/tier/environment.",
			})
		}

		// Rule: Resource Limits
		for _, container := range pod.Spec.Containers {
			if container.Resources.Limits.Cpu().IsZero() || container.Resources.Limits.Memory().IsZero() {
				issues = append(issues, AuditIssue{
					Category:    "Efficiency",
					Resource:    "Pod",
					Name:        fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
					Message:     fmt.Sprintf("Container '%s' has no resource limits", container.Name),
					Severity:    "High",
					Remediation: "Define resources.limits for CPU and Memory in your deployment manifest.",
				})
			}

			// Advanced Security Check: Running as Root
			if container.SecurityContext == nil || container.SecurityContext.RunAsNonRoot == nil || !*container.SecurityContext.RunAsNonRoot {
				issues = append(issues, AuditIssue{
					Category:    "Security",
					Resource:    "Pod",
					Name:        fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
					Message:     fmt.Sprintf("Container '%s' might be running as root", container.Name),
					Severity:    "High",
					Remediation: "Set securityContext.runAsNonRoot: true to prevent root privilege escalation.",
				})
			}
		}
	}
	return issues
}

func auditCosts(clientset *kubernetes.Clientset) []AuditIssue {
	var issues []AuditIssue

	// Check 1: Unused Persistent Volumes (PVs that are 'Available' but not 'Bound')
	pvs, _ := clientset.CoreV1().PersistentVolumes().List(context.TODO(), metav1.ListOptions{})
	for _, pv := range pvs.Items {
		if pv.Status.Phase == corev1.VolumeAvailable {
			issues = append(issues, AuditIssue{
				Category:    "Cost",
				Resource:    "PV",
				Name:        pv.Name,
				Message:     "Unused Disk (PersistentVolume is Available but not Bound)",
				Severity:    "High",
				Remediation: "Delete unused PersistentVolumes to save storage costs or bind them to a PVC.",
			})
		}
	}

	// Check 2: Unused LoadBalancers (Services of type LoadBalancer without an external IP)
	svcs, _ := clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	for _, svc := range svcs.Items {
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			// If it's a LoadBalancer but has no ingress points, it might be orphaned or pending (costing money)
			if len(svc.Status.LoadBalancer.Ingress) == 0 {
				issues = append(issues, AuditIssue{
					Category:    "Cost",
					Resource:    "Service",
					Name:        fmt.Sprintf("%s/%s", svc.Namespace, svc.Name),
					Message:     "LoadBalancer without Active Ingress (Potential orphaned cost)",
					Severity:    "Medium",
					Remediation: "Check if the LoadBalancer is still needed or fix the cloud provider integration.",
				})
			}
		}
	}

	// Check 3: Old ReplicaSets (Potential cleanup for storage/cost)
	rss, _ := clientset.AppsV1().ReplicaSets("").List(context.TODO(), metav1.ListOptions{})
	for _, rs := range rss.Items {
		if *rs.Spec.Replicas == 0 {
			issues = append(issues, AuditIssue{
				Category:    "Cost",
				Resource:    "ReplicaSet",
				Name:        fmt.Sprintf("%s/%s", rs.Namespace, rs.Name),
				Message:     "Orphaned ReplicaSet with 0 replicas",
				Severity:    "Low",
				Remediation: "Clean up old ReplicaSets to keep the cluster history clean and reduce metadata overhead.",
			})
		}
	}

	return issues
}

func renderTable(issues []AuditIssue) {
	if len(issues) == 0 {
		color.Green("\n✨ No issues found! Your cluster is Google-standard clean.")
		return
	}

	fmt.Println("\n📊 KubeGuard Audit Report")

	// Standart Go tabwriter kullanımı
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	
	// Başlıklar (Daha geniş ve profesyonel)
	fmt.Fprintln(w, "CATEGORY\tRESOURCE\tNAME\tMESSAGE\tSEVERITY\tREMEDIATION")
	fmt.Fprintln(w, "--------\t--------\t----\t-------\t--------\t-----------")

	for _, issue := range issues {
		var coloredSeverity string
		switch issue.Severity {
		case "High":
			coloredSeverity = color.RedString(issue.Severity)
		case "Medium":
			coloredSeverity = color.YellowString(issue.Severity)
		default:
			coloredSeverity = color.CyanString(issue.Severity)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			issue.Category,
			issue.Resource,
			truncate(issue.Name, 25),
			truncate(issue.Message, 40),
			coloredSeverity,
			color.HiBlackString(issue.Remediation),
		)
	}
	w.Flush()
}

func renderJSON(issues []AuditIssue) {
	data, err := json.MarshalIndent(issues, "", "  ")
	if err != nil {
		fmt.Printf("Error generating JSON: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}
