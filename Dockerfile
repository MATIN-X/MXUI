#===============================================================================
#
#          FILE: Dockerfile
#
#   DESCRIPTION: MR-X VPN Panel Docker Image
#
#        AUTHOR: MR-X Team
#       VERSION: 1.0.0
#
#   BUILD:
#       docker build -t Mxui:latest .
#
#   RUN:
#       docker run -d --name Mxui --network host Mxui:latest
#
#===============================================================================

#===============================================================================
# Stage 1: Build the Go binary
#===============================================================================
FROM golang:1.22-alpine AS builder

# Build arguments
ARG VERSION=1.0.0
ARG BUILD_TIME
ARG GIT_COMMIT

# Install build dependencies
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    ca-certificates \
    tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY Core/ ./Core/

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
        -X 'main.Version=${VERSION}' \
        -X 'main.BuildTime=${BUILD_TIME}' \
        -X 'main.GitCommit=${GIT_COMMIT}'" \
    -o /build/Mxui \
    ./Core/main.go

#===============================================================================
# Stage 2: Download Xray
#===============================================================================
FROM alpine:3.19 AS xray-downloader

# Install dependencies
RUN apk add --no-cache curl jq unzip

# Download latest Xray
RUN XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name') && \
    ARCH=$(uname -m) && \
    case $ARCH in \
        x86_64) XRAY_ARCH="64" ;; \
        aarch64) XRAY_ARCH="arm64-v8a" ;; \
        armv7l) XRAY_ARCH="arm32-v7a" ;; \
        *) XRAY_ARCH="64" ;; \
    esac && \
    curl -sL -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" && \
    mkdir -p /xray && \
    unzip /tmp/xray.zip -d /xray && \
    chmod +x /xray/xray

# Download GeoIP files
RUN curl -sL -o /xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" && \
    curl -sL -o /xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

#===============================================================================
# Stage 3: Final image
#===============================================================================
FROM alpine:3.19

# Labels
LABEL maintainer="MR-X Team" \
      org.opencontainers.image.title="MR-X VPN Panel" \
      org.opencontainers.image.description="Professional VPN Management Panel" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="MR-X Team" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/MR-X-Panel/MR-X"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    bash \
    jq \
    sqlite \
    iptables \
    ip6tables \
    iproute2 \
    wireguard-tools \
    && rm -rf /var/cache/apk/*

# Create non-root user (optional, disabled for VPN functionality)
# RUN addgroup -S Mxui && adduser -S Mxui -G Mxui

# Create directories
RUN mkdir -p /app/{bin,data,logs,web,certs,backups}

# Copy binary from builder
COPY --from=builder /build/Mxui /app/bin/Mxui

# Copy Xray from downloader
COPY --from=xray-downloader /xray/xray /app/bin/xray
COPY --from=xray-downloader /xray/geoip.dat /app/data/geoip.dat
COPY --from=xray-downloader /xray/geosite.dat /app/data/geosite.dat

# Copy web assets
COPY Web/ /app/web/

# Copy configuration
COPY config.yaml /app/config.yaml

# Set permissions
RUN chmod +x /app/bin/Mxui /app/bin/xray && \
    chmod 755 /app && \
    chmod 700 /app/data /app/logs /app/certs /app/backups

# Set working directory
WORKDIR /app

# Environment variables
ENV Mxui_CONFIG=/app/config.yaml \
    Mxui_DATA_DIR=/app/data \
    Mxui_LOG_DIR=/app/logs \
    Mxui_HOST=0.0.0.0 \
    Mxui_PORT=8443 \
    Mxui_API_PORT=8080 \
    TZ=UTC \
    GOGC=100

# Expose ports
# Panel web interface
EXPOSE 8443
# API server
EXPOSE 8080
# Default Xray ports
EXPOSE 443
EXPOSE 80
EXPOSE 8443
# WireGuard
EXPOSE 51820/udp

# Volumes
VOLUME ["/app/data", "/app/logs", "/app/certs", "/app/backups"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -sf http://localhost:${Mxui_PORT}/health || exit 1

# Entry point
ENTRYPOINT ["/app/bin/Mxui"]

# Default command
CMD ["serve", "--config", "/app/config.yaml"]
