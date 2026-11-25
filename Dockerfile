# syntax=docker/dockerfile:1.7
FROM rust:1.86-slim AS builder

WORKDIR /src
COPY Cargo.toml ./
COPY crates ./crates

RUN cargo build --release -p morph-core

FROM debian:bookworm-slim AS runtime

RUN useradd --create-home --shell /usr/sbin/nologin morph
WORKDIR /app

COPY --from=builder /src/target/release/morph-os /usr/local/bin/morph-os
COPY plugins ./plugins
COPY wasm ./wasm

USER morph
EXPOSE 8787

ENTRYPOINT ["morph-os"]
CMD ["version"]
