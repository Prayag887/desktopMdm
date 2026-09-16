# syntax=docker/dockerfile:1.7
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=emi-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=emi-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=emi-control-target,target=/src/target \
    cargo build --locked --release --package emi-control-plane && \
    install -Dm755 target/release/emi-control-plane /out/emi-control-plane && \
    mkdir -p /out/data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build --chown=65532:65532 /out/emi-control-plane /usr/local/bin/emi-control-plane
COPY --from=build --chown=65532:65532 /out/data /data
WORKDIR /data
USER 65532:65532
ENV BIND_ADDR=0.0.0.0:3000 \
    DATABASE_URL=sqlite:///data/emi-mdm.db?mode=rwc \
    HEALTHCHECK_ADDR=127.0.0.1:3000 \
    RUST_LOG=emi_control_plane=info,tower_http=info
EXPOSE 3000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 CMD ["/usr/local/bin/emi-control-plane", "--health-check"]
ENTRYPOINT ["emi-control-plane"]
