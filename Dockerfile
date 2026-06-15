# Optional container packaging. The product is the static binary; this image is
# a thin wrapper for users who prefer compose. Final image is ~7 MB (scratch).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/ip-watch ./cmd/ip-watch

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/ip-watch /usr/local/bin/ip-watch
# Bind all interfaces inside the container so a published port works. ip-watch
# refuses to start on a non-loopback address without auth, so you MUST provide
# IPWATCH_AUTH_USERNAME/PASSWORD (recommended) or set IPWATCH_INSECURE=1.
ENV IPWATCH_CONFIG=/data/config.json
ENV IPWATCH_LISTEN=0.0.0.0:8080
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/ip-watch", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/ip-watch"]
CMD ["serve"]
