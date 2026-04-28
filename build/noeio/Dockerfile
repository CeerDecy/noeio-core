FROM rust:1.94 AS builder

WORKDIR /app
COPY . .
RUN cargo build --release -p noeio

FROM scratch AS export
COPY --from=builder /app/target/release/noeio /noeio
