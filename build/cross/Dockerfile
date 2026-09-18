ARG RUST_IMAGE=rust:1.94-bookworm
FROM ${RUST_IMAGE}

ARG ZIG_VERSION=0.13.0
ARG CARGO_ZIGBUILD_VERSION=0.20.1
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-venv gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/zig \
    && /opt/zig/bin/pip install --no-cache-dir ziglang==${ZIG_VERSION} \
    && ln -s /opt/zig/lib/python3.11/site-packages/ziglang/zig /usr/local/bin/zig
RUN cargo install cargo-zigbuild --version ${CARGO_ZIGBUILD_VERSION} --locked \
    && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
       x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-gnu

ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
    CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++ \
    AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar \
    CARGO_TARGET_DIR=/cache/target \
    CARGO_HOME=/cache/cargo \
    XDG_CACHE_HOME=/cache/xdg \
    MACOSX_DEPLOYMENT_TARGET=11.0
COPY build/cross/entrypoint.sh /usr/local/bin/build-binaries
ENTRYPOINT ["bash", "/usr/local/bin/build-binaries"]
