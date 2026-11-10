FROM golang:1.26-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/api/main.go

FROM alpine:3.21 AS migrate
ARG TARGETARCH
# pressly/goose release binaries use x86_64/arm64, not Docker's amd64 label.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) GOOSE_ARCH=x86_64 ;; \
      arm64) GOOSE_ARCH=arm64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    wget -qO /usr/local/bin/goose "https://github.com/pressly/goose/releases/download/v3.26.0/goose_linux_${GOOSE_ARCH}"; \
    chmod +x /usr/local/bin/goose
COPY --from=build /app/migrations /migrations
ENTRYPOINT ["goose", "-dir", "/migrations", "postgres"]

FROM alpine:3.21 AS prod
ARG PORT=8080
ENV PORT=${PORT}
WORKDIR /app
RUN apk add --no-cache wget \
    && addgroup -S app && adduser -S app -G app
COPY --from=build /app/main /app/main
USER app
EXPOSE ${PORT}
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/health" | grep -q '"status":"up"' || exit 1
CMD ["./main"]
