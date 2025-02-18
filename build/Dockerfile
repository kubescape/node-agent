FROM gcr.io/distroless/static-debian12:latest

COPY node-agent /usr/bin/node-agent
COPY configuration/ig-config.yaml /root/.ig/config.yaml

ARG image_version
ENV RELEASE=$image_version

WORKDIR /root
ENTRYPOINT ["node-agent"]
