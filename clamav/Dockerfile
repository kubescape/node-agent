ARG CLAMAV_VERSION

FROM ubuntu:23.10 as builder
ARG SOCKS_PROXY
ENV SOCKS_PROXY=$SOCKS_PROXY
RUN apt-get update && apt-get install -y python3 python3-pip clamav
COPY create-filtered-clam-db.sh /
RUN /create-filtered-clam-db.sh

FROM clamav/clamav-debian:${CLAMAV_VERSION}
RUN apt-get update && apt-get install -y netcat
COPY ./init.sh /init
RUN mkdir -p /var/lib/clamav || true
COPY --from=builder main.cud /var/lib/clamav/main.cud
RUN chmod +x /init && chown clamav:clamav /var/lib/clamav
ENV CLAMAV_NO_FRESHCLAMD=true