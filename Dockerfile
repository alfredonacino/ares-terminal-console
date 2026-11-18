# ARES Suite standard image: ares-terminal-console (server). Non-root, health-checked, state under /app/data.
#
# This is the web edition: sign-in with users, 2FA and SSO, then split-pane terminals in the browser.
# The shells run inside this container, as the unprivileged user `app`, so what a pane can reach is
# what the container can reach. Put it behind TLS (the suite's web tier and edge proxy do that).
#
#   docker run -d -p 3222:3222 -v ares-terminal:/app/data docker.cybercontrol.tech/ares/ares-terminal-console
#   docker exec <container> cat /app/data/initial-admin-password.txt   # first sign-in as aresadmin
FROM python:3.13-slim
ARG APP_VERSION=0.0.0
LABEL org.opencontainers.image.title="ARES Terminal Console" \
      org.opencontainers.image.description="Split-pane web terminals with users, 2FA, SSO (Entra ID, SAML, LDAP), backups and audit" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="ARES" \
      org.opencontainers.image.url="https://ares-terminal-console.nacino.net"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOST=0.0.0.0 PORT=3222 APP_VERSION=${APP_VERSION} \
    DATA_DIR=/app/data SHELL=/bin/bash LANG=C.UTF-8 LOG_FORMAT=json
# The tools a terminal is for. Kept deliberately to the everyday set.
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      bash openssh-client ca-certificates curl iproute2 iputils-ping dnsutils \
      procps less nano vim-tiny git rsync jq netcat-openbsd >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --home-dir /home/app --shell /bin/bash app
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -q -r requirements.txt
COPY --chown=root:root . .
RUN mkdir -p /app/data /app/logs && chown -R app:app /app/data /app/logs
USER 10001
EXPOSE 3222
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ['PORT']+'/healthz',timeout=4).status==200 else 1)"
CMD ["python", "app/main.py"]
