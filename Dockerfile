# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o /out/rustdesk-panel-api ./cmd/api

FROM alpine:3.20
RUN apk add --no-cache tzdata ca-certificates \
    && adduser -D -u 10001 panel
USER panel
WORKDIR /app
COPY --from=build /out/rustdesk-panel-api /app/rustdesk-panel-api
EXPOSE 8080
ENTRYPOINT ["/app/rustdesk-panel-api"]
