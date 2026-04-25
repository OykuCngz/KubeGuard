# 🛡️ KubeGuard: Professional Kubernetes Auditor

KubeGuard is a high-performance CLI tool designed to audit Kubernetes clusters for security misconfigurations, efficiency gaps, and cost optimization opportunities. Built with Google-scale infrastructure standards in mind.

## 🚀 Features

- **Security Auditing**: Detects privileged containers, root access risks, and security context misconfigurations.
- **Efficiency Checks**: Identifies containers without CPU/Memory limits to prevent "noisy neighbor" issues.
- **Cost Optimization**: Scans for orphaned LoadBalancers and unused Persistent Volumes.
- **Namespace Filtering**: Audit specific namespaces or the entire cluster.
- **CI/CD Ready**: Supports JSON output for automated pipeline integrations.
- **Demo Mode**: Showcase functionality even without an active cluster connection.

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/KubeGuard.git
cd KubeGuard
go mod tidy
go build -o kubeguard main.go
```

## 🛠️ Usage

### Basic Audit
```bash
go run main.go audit
```

### Audit Specific Namespace
```bash
go run main.go audit --namespace default
```

### JSON Output for Automation
```bash
go run main.go audit --json
```

## 🛠️ Built With
- [Go](https://golang.org/) - The language of the cloud.
- [Cobra](https://github.com/spf13/cobra) - Modern CLI framework.
- [Client-Go](https://github.com/kubernetes/client-go) - Official Kubernetes Go client.

## 👨‍💻 Author
- Your Name - [Your LinkedIn](your-linkedin-url)

---
*Developed with focus on Google Warsaw Engineering Standards.*
