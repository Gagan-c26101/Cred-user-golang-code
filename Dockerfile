# Stage 1: Build with CGO enabled using bullseye to match runtime
FROM golang:1.22-bullseye AS builder

ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64

RUN apt-get update && apt-get install -y gcc

WORKDIR /app
COPY . .

RUN go build -o app .

# Stage 2: Runtime on same base (bullseye-slim)
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y libsqlite3-0 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/app .
CMD ["./app"]
