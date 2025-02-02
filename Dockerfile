FROM rust:1.82.0 AS builder
WORKDIR /usr/src/emissary

RUN apt-get update && apt-get install -y cmake

COPY Cargo.toml Cargo.lock ./
COPY emissary-core ./emissary-core
COPY emissary-cli ./emissary-cli
COPY emissary-util ./emissary-util

RUN cargo install --profile testnet --path emissary-cli

FROM debian:bookworm
RUN apt-get update && apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/emissary-cli /usr/local/bin/emissary-cli

CMD ["emissary-cli"]
