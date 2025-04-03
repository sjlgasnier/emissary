FROM rust:1.82.0 AS builder
WORKDIR /usr/src/emissary

ARG PROFILE=release

RUN apt-get update && apt-get install -y cmake

RUN cargo install --profile $PROFILE --no-default-features emissary-cli

FROM debian:bookworm
COPY --from=builder /usr/local/cargo/bin/emissary-cli /usr/local/bin/emissary-cli

CMD ["emissary-cli"]
