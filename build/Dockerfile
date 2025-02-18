FROM gcr.io/distroless/static-debian12:latest

WORKDIR /root
ENTRYPOINT ["node-agent"]

COPY node-agent /usr/local/bin/node-agent
COPY configuration/ig-config.yaml /root/.ig/config.yaml
