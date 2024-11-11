# NodeAgent
[![Version](https://img.shields.io/github/v/release/kubescape/node-agent)](https://github.com/kubescape/node-agent/releases)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kubescape/node-agent/badge)](https://securityscorecards.dev/viewer/?uri=github.com/kubescape/node-agent)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer.svg?type=shield&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer?ref=badge_shield&issueType=license)
[![Stars](https://img.shields.io/github/stars/kubescape/node-agent?style=social)](https://github.com/kubescape/node-agent/stargazers)

NodeAgent is a component of Kubescape that enables node-level security scanning and monitoring.
It uses eBPF technology to monitor the system and provides real-time security insights.

## Running Node Agent in Kubernetes
This is the recommended way to run the Node Agent.
You can run the Node Agent in a Kubernetes cluster as part of Kubescape by using helm.
Please refer to the [docs](https://kubescape.io/docs/) for more information.

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

## System Requirements
1. The node agent uses eBPF, so make sure your system supports it.
2. It uses `CO-RE`, so make sure your kernel version is 5.4 or higher.


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
