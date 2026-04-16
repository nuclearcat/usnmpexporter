# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o usnmp_exporter .

# Runtime stage
FROM alpine:3.18
COPY --from=builder /app/usnmp_exporter /usr/local/bin/usnmp_exporter
EXPOSE 9116
CMD ["/usr/local/bin/usnmp_exporter"]
