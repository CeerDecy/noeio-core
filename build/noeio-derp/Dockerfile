FROM m.daocloud.io/docker.io/rust:1.94 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release -p noeio-derp

FROM m.daocloud.io/docker.io/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/noeio-derp /usr/local/bin/noeio-derp

ENTRYPOINT ["noeio-derp","boot"]
