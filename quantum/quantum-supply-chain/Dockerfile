FROM golang:1.22-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o quantum-supply-chain ./cmd

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/quantum-supply-chain .
EXPOSE 8085
CMD ["./quantum-supply-chain"]
