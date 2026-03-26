FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go env -w GOPROXY=direct
RUN go mod tidy
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o dashboard-api .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/dashboard-api .
CMD ["./dashboard-api"]
