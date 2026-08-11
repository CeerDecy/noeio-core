FROM m.daocloud.io/docker.io/rust:1.94 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release -p noeio

FROM m.daocloud.io/docker.io/debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/noeio /usr/local/bin/noeio

ENTRYPOINT ["noeio","boot"]
