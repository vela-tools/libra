FROM rust:1.99.1-trixie AS chef

RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /libra

FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /libra/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bin libra

FROM debian:trixie-20261027-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The key store and the policy directory belong to the user Libra runs as, never to root: whoever
# can write either one decides who gets in.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin libra \
    && mkdir -p /etc/libra/policies /var/lib/libra \
    && chown libra:libra /var/lib/libra

COPY --from=builder /libra/target/release/libra /usr/local/bin/libra

USER libra
EXPOSE 5667
VOLUME ["/var/lib/libra"]

ENTRYPOINT ["/usr/local/bin/libra"]
