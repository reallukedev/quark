# Quark, the XMPP server, in one small image.
#   docker build -t quark .
#   docker run -e QUARK_DOMAIN=chat.example.com -e QUARK_ADMINS=you@chat.example.com \
#     -e QUARK_TURN_EXTERNAL_IP=203.0.113.7 \
#     -v quark-config:/etc/quark -v quark-data:/var/lib/quark \
#     -p 5222:5222 -p 5223:5223 -p 5269:5269 -p 5280:5280 -p 3478:3478/udp -p 3478:3478 \
#     -p 49160-49200:49160-49200/udp quark
# QUARK_TURN_EXTERNAL_IP is the host's public IP: inside the container the call relay only sees
# its bridge address, which phones can't reach, so calls through the relay fail without it.
# A reverse proxy in another container must be listed in [http] trusted_proxies (docs/config.md).

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml clippy.toml ./
COPY crates crates
RUN cargo build --release --locked -p quark --bin quark

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 990 quark \
    && useradd --system --uid 990 --gid quark --home-dir /var/lib/quark --shell /usr/sbin/nologin quark \
    && mkdir -p /etc/quark/certs /var/lib/quark \
    && chown -R quark:quark /etc/quark /var/lib/quark
COPY --from=build /src/target/release/quark /usr/local/bin/quark
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
ENV QUARK_CONFIG=/etc/quark/quark.toml
VOLUME ["/etc/quark", "/var/lib/quark"]
# 5222 clients (STARTTLS), 5223 clients (direct TLS), 5269/5270 servers, 5280 web, 3478 calls relay.
EXPOSE 5222 5223 5269 5270 5280 3478 3478/udp 49160-49200/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD echo '{"cmd":"status"}' | quark ctl | grep -q '"ok":true' || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["run"]
