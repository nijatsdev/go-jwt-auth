FROM golang:1.26-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/api/main.go

FROM alpine:3.21 AS migrate
ARG TARGETARCH
ADD https://github.com/pressly/goose/releases/download/v3.24.3/goose_linux_${TARGETARCH} /usr/local/bin/goose
RUN chmod +x /usr/local/bin/goose
COPY --from=build /app/migrations /migrations
ENTRYPOINT ["goose", "-dir", "/migrations", "postgres"]

FROM alpine:3.21 AS prod
WORKDIR /app
COPY --from=build /app/main /app/main
EXPOSE ${PORT}
CMD ["./main"]
