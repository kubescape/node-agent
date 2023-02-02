## sniffer

1. Compile relevant binaries by running the following script:

```sh
./install_dependencies.sh
```

<i>This step can take ~15 minutes depending on your machine.</i>

2. Build Sneeffer

```
go build -o sniffer .
```

3. Run minikube:

```
minikube start
```

4. Run Sneeffer:

```
sudo SNEEFFER_CONF_FILE_PATH=./configuration/SneefferConfigurationFile.txt HOME=<your home directory> ./sniffer
```