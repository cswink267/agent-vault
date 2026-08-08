FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/vault-server ./cmd/vault-server \
 && CGO_ENABLED=0 go build -o /out/vault ./cmd/vault \
 && CGO_ENABLED=0 go build -o /out/vault-mcp ./cmd/vault-mcp

FROM alpine:3.20
RUN adduser -D -u 1000 vault
RUN mkdir -p /data && chown vault:vault /data
COPY --from=build /out/vault-server /out/vault /out/vault-mcp /usr/local/bin/
USER vault
ENV PORT=8080 AGENT_VAULT_DATA_DIR=/data
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["vault-server"]
