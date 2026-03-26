FROM golang:1.22-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o quantum-dashboard-api ./cmd

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/quantum-dashboard-api .
EXPOSE 8088
CMD ["./quantum-dashboard-api"]
