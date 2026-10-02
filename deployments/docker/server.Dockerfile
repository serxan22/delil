# syntax=docker/dockerfile:1.7
# DƏLİL server and CLI. Static binaries on distroless, running as non-root.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
COPY pkg ./pkg
ARG VERSION=0.1.0
ARG COMMIT=unknown
ARG DATE=unknown
ENV CGO_ENABLED=0
RUN LDFLAGS="-s -w -X github.com/serxan22/delil/internal/version.Version=${VERSION} \
      -X github.com/serxan22/delil/internal/version.Commit=${COMMIT} -X github.com/serxan22/delil/internal/version.Date=${DATE}" && \
    go build -trimpath -ldflags "$LDFLAGS" -o /out/delil-server ./cmd/delil-server && \
    go build -trimpath -ldflags "$LDFLAGS" -o /out/delil ./cmd/delil && \
    mkdir -p /out/data/exports /out/data/anchors

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="DƏLİL server" \
      org.opencontainers.image.description="Cryptographically verifiable audit infrastructure" \
      org.opencontainers.image.source="https://github.com/serxan22/delil" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/delil-server /out/delil /usr/local/bin/
COPY --from=build --chown=65532:65532 /out/data /var/lib/delil
USER 65532:65532
ENV DELIL_HTTP_ADDR=:8080 DELIL_DATA_DIR=/var/lib/delil
EXPOSE 8080
VOLUME ["/var/lib/delil"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=6 CMD ["/usr/local/bin/delil-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/delil-server"]
CMD ["serve"]
