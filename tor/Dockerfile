FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends tor ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Prepare data dir
RUN mkdir -p /var/lib/tor && chown -R debian-tor:debian-tor /var/lib/tor

COPY torrc /etc/tor/torrc

# Fix ownership at start, then run tor
CMD ["/bin/sh","-c","chmod 700 /var/lib/tor && chown -R debian-tor:debian-tor /var/lib/tor && exec /usr/bin/tor -f /etc/tor/torrc"]

