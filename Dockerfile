ARG RUST_VERSION=1

FROM rust:${RUST_VERSION}-bookworm AS builder

# Use a shell that exists whenever it encounters errors
SHELL ["/bin/bash", "-xo", "pipefail", "-c"]

# Install OS dependencies
RUN apt update \
    && apt install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* /tmp/*

WORKDIR /build
COPY . /build

# Run the build command.
# Note that this mounts several cache directories to speed up subsequent builds.
# After build, we move the binaries out of the target directory because that directory
# will not be available in the next steps (as it is a cached directory).
RUN --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target/ \
    cargo build --locked --release \
    && mkdir -p /build/artifacts \
    && cp target/release/ntp-daemon /build/artifacts \
    && cp target/release/ntp-ctl /build/artifacts \
    && cp target/release/ntp-metrics-exporter /build/artifacts

# Setup the final actual runner image stage
FROM debian:bookworm-slim AS runner

# Install CA certificates for the runner
RUN apt update \
    && apt install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* /tmp/*

# Copy compiled binaries from the builder stage
COPY --from=builder /build/artifacts/ntp-daemon /usr/local/bin/ntp-daemon
COPY --from=builder /build/artifacts/ntp-ctl /usr/local/bin/ntp-ctl
COPY --from=builder /build/artifacts/ntp-metrics-exporter /usr/local/bin/ntp-metrics-exporter

# Setup a user and group for the runner
ARG USER=ntpd-rs
ENV USER=${USER}
ARG UID=10001
ENV UID=${UID}
ARG GID=10001
ENV GID=${GID}
RUN addgroup --system --gid "${GID}" "${USER}" \
    && adduser \
        --system \
        --disabled-login \
        --shell /bin/bash \
        --uid "${UID}" \
        --gid "${GID}" \
        "${USER}"
USER ${USER}

CMD ["/usr/local/bin/ntp-daemon"]
