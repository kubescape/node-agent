## NodeAgent
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kubescape/node-agent/badge)](https://securityscorecards.dev/viewer/?uri=github.com/kubescape/node-agent)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer.svg?type=shield&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer?ref=badge_shield&issueType=license)

1. Run minikube:

```
minikube start
```

2. Run NodeAgent:

```
sudo SNIFFER_CONFIG=./configuration/SnifferConfigurationFile.json ./sniffer
```

## Limitations:
1. This feature is using EBPF technology that is implemented only on linux.
2. the linux kernel version that supported it 5.4 and above.


## Debugging
# file for vscode:
```
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Package",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}",
            "env": {
                "SNIFFER_CONFIG": "${workspaceFolder}/configuration/SnifferConfigurationFile.json"
            },
            "console": "integratedTerminal",
            "asRoot": true
        }
    ]
}

```
## Changelog

Kubescape Node-agent changes are tracked on the [release](https://github.com/kubescape/node-agent/releases) page
