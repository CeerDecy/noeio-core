FROM rust:1.94 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release -p noeio

FROM scratch AS export
COPY --from=builder /app/target/release/noeio /noeio
