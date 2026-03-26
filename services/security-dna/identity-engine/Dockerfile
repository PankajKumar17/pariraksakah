FROM rust:1.75 AS builder

WORKDIR /usr/src/app
COPY Cargo.toml .
# Create dummy src/main.rs to cache dependencies
RUN mkdir src
RUN echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/dna_identity_engine*

# Compile real source
COPY src ./src
# Install system packages required
RUN apt-get update && apt-get install -y cmake clang pkg-config libssl-dev build-essential && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM debian:bookworm-slim
# Additional system tools used by hardware fingerprint collector
RUN apt-get update && apt-get install -y iproute2 linux-perf swtpm procps && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/dna_identity_engine /usr/local/bin/dna_identity_engine
CMD ["dna_identity_engine"]
