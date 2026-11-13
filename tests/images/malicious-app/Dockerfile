FROM golang:1.27.4-alpine3.24 AS builder
WORKDIR /go/src/app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o malicious ./malicious.go

FROM alpine:3.24
RUN apk --no-cache upgrade
COPY --from=builder /go/src/app/malicious /malicious
ENTRYPOINT ["/malicious"]
