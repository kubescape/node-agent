# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM python:3.14-slim-trixie AS builder
ARG SOCKS_PROXY
ENV SOCKS_PROXY=$SOCKS_PROXY
RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
    clamav \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
COPY create-filtered-clam-db.sh /
RUN /create-filtered-clam-db.sh

ARG CLAMAV_VERSION
FROM --platform=$BUILDPLATFORM clamav/clamav-debian:${CLAMAV_VERSION}
RUN apt-get -y update && apt-get install -y --no-install-recommends \
    netcat-traditional
RUN mkdir -p /var/lib/clamav || true
COPY ./init.sh /init
COPY --from=builder main.cud /var/lib/clamav/main.cud
RUN chmod +x /init && chown clamav:clamav /var/lib/clamav
ENV CLAMAV_NO_FRESHCLAMD=true
USER clamav
