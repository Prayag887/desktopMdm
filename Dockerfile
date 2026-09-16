FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release --package emi-control-plane

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data emi
COPY --from=build /src/target/release/emi-control-plane /usr/local/bin/emi-control-plane
WORKDIR /data
USER emi
ENV BIND_ADDR=0.0.0.0:3000 DATABASE_URL=sqlite:///data/emi-mdm.db?mode=rwc
EXPOSE 3000
ENTRYPOINT ["emi-control-plane"]

