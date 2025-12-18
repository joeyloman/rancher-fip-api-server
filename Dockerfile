FROM docker.io/golang:1.25-alpine3.23 AS builder
RUN mkdir /src /deps
RUN apk update && apk add git build-base binutils-gold
WORKDIR /deps
ADD go.mod /deps
RUN go mod download
ADD / /src
WORKDIR /src
RUN go build -a -o rancher-fip-api-server cmd/api-server/main.go
FROM docker.io/alpine:3.23
RUN adduser -S -D -H -h /app rancher-fip-api-server
USER rancher-fip-api-server
COPY --from=builder /src/rancher-fip-api-server /app/
WORKDIR /app
ENTRYPOINT ["./rancher-fip-api-server"]