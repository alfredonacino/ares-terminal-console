# ARES Terminal Console, served to a browser from a container.
#
#   docker run -d -p 8080:8080 -v ares-terminal:/data docker.cybercontrol.tech/ares/terminal-console
#   docker logs <container>     # prints the link, with its access token
#
# The shells run inside the container, as an unprivileged user, so what a pane
# can reach is what the container can reach: give it the tools and the mounts
# you want, nothing more. The access token is always required here, because
# this listens beyond loopback; set ARES_ACCESS_TOKEN to choose it, or read the
# one kept in /data/access-token. Put TLS in front before it leaves a private
# network.
FROM python:3.13-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="ARES Terminal Console" \
      org.opencontainers.image.description="Split-pane terminals in a browser, with broadcast, keep-alive and a connection history" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/alfredonacino/ares-terminal-console"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SHELL=/bin/bash LANG=C.UTF-8
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      bash openssh-client ca-certificates curl iproute2 iputils-ping dnsutils \
      procps less nano vim-tiny git rsync jq netcat-openbsd >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /bin/bash ares \
 && mkdir -p /data && chown ares:ares /data
WORKDIR /opt/ares-terminal-console
COPY --chown=root:root apexmod apexmodule.toml ./
COPY --chown=root:root app ./app
USER 10001
WORKDIR /home/ares
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/health')"
ENTRYPOINT ["python", "/opt/ares-terminal-console/apexmod", "run", "--host", "0.0.0.0", "--port", "8080", "--data-dir", "/data", "--no-open"]
