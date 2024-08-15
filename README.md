# NodeAgent
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kubescape/node-agent/badge)](https://securityscorecards.dev/viewer/?uri=github.com/kubescape/node-agent)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer.svg?type=shield&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer?ref=badge_shield&issueType=license)

## Prerequisites
1. [Minikube](https://minikube.sigs.k8s.io/docs/start/)
Start minikube with the following command:
```
minikube start
```
2. Linux kernel version 5.4 and above.


## Running the Node Agent
Make sure to set the `NODE_NAME` environment variable to the name of the node you want to scan.
Also make sure you have the `KUBECONFIG` environment variable set to the path of your kubeconfig file.
You can then build the binary by running:
```
go build .
```
Then run the binarty with root privileges:
```
sudo ./node-agent
```

## Running Node Agent in Kubernetes
You can run the Node Agent in a Kubernetes cluster as part of Kubescape by using helm.
Please refer to the [docs](https://kubescape.io/docs/) for more information.

## Limitations:
1. This feature is using eBPF technology that is implemented only on linux.
2. the linux kernel version that supported it 5.4 and above.


## Debugging
# file for vscode:
```
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Package",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}/main.go",
            "env": {
                "NODE_NAME": "<node name>",
                "KUBECONFIG": "<path_to_kubeconfig>",
            },
            "console": "integratedTerminal",
            "asRoot": true,
        }
    ]
}


```
## Changelog

Kubescape Node-agent changes are tracked on the [release](https://github.com/kubescape/node-agent/releases) page
