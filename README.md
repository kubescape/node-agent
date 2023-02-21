## sniffer
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer?ref=badge_shield)


1. Run minikube:

```
minikube start
```

2. Run Sniffer:

```
sudo SNIFFER_CONFIG=./configuration/SnifferConfigurationFile.json ./sniffer
```

## Limitations:
1. This feature is using EBPF technology that is implemented only on linux.
2. the linux kernel version that supported it 4.14


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

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer?ref=badge_large)