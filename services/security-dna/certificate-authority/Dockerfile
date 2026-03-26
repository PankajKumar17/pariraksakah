FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod ./
# No go.sum yet, so we will initialize it in docker build or here
RUN go env -w GOPROXY=direct
RUN go install -v github.com/cloudflare/circl/sign/dilithium@latest || true
RUN go mod tidy
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o ca .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/ca .
CMD ["./ca"]
