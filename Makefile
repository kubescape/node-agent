install-deps:
	./deps/install_dependencies.sh

build:
	go build -o sniffer .