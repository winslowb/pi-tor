FROM python:3.12-slim-bookworm

# iptables + iproute2 are needed for bin/pi-tor-rules.sh inside the container
# (CAP_NET_ADMIN is granted via docker-compose cap_add).
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables iproute2 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PI_TOR_PROJECT_DIR=/project

WORKDIR /app
COPY . /app/

# no EXPOSE: compose runs the ui with network_mode: host
CMD ["python", "app.py"]
