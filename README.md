## sniffer

1. Run minikube:

```
minikube start
```

2. Run Sneeffer:

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
                "SNEEFFER_CONFIG": "${workspaceFolder}/configuration/SnifferConfigurationFile.json"
            },
            "console": "integratedTerminal",
            "asRoot": true
        }
    ]
}

```