# syntax=docker/dockerfile:1

# The UI in a container: `barbican ui-proxy` serves it and passes its API to an agent on the host, through the unix
# socket the agent's `ui.socket` makes (see the README). The agent itself runs on the host, not in here.

# The frontend is the same for every architecture: build it once, natively.
FROM --platform=$BUILDPLATFORM node:26.13.0-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# A static musl binary, built natively for each target platform.
FROM rust:1.99.1-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo .cargo
COPY .sqlx .sqlx
COPY crates crates
COPY --from=web /src/web/dist web/dist
# Appended to the version (`--version`), e.g. -dev+abc1234 for a build of a branch.
ARG BARBICAN_VERSION_SUFFIX=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    cargo build --locked --release -p barbican; \
    mkdir -p /rootfs; \
    cp target/release/barbican /rootfs/barbican

FROM scratch
COPY --from=build /rootfs/ /
LABEL org.opencontainers.image.source="https://github.com/nikarh/barbican" \
      org.opencontainers.image.description="barbican's web UI, for an agent on the host" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
# nobody:nogroup. Any other uid:gid works too (`user:` in compose); it needs the socket's group (`group_add:`).
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/barbican", "healthcheck"]
ENTRYPOINT ["/barbican", "ui-proxy"]
