FROM node:24.22.1-bookworm-slim AS rea-runtime

WORKDIR /opt/rea-runtime
COPY guest/rea-runtime/package.json guest/rea-runtime/package-lock.json ./
# Replit rewrites lockfile tarball URLs to its private package proxy. Normalize
# those URLs so this image can be built on the Vultr/production build host.
RUN sed -i 's#http://package-firewall\.replit\.internal/npm/#https://registry.npmjs.org/#g' package-lock.json \
    && npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONPATH=/opt/veridict \
    REA_ENTRYPOINT=/opt/rea-runtime/node_modules/rea-agents/scripts/rea.mjs

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rea-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=rea-runtime /opt/rea-runtime/node_modules /opt/rea-runtime/node_modules

WORKDIR /opt/veridict
COPY guest/requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
    && python -m playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /root/.cache/pip /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home --home-dir /home/veridict veridict \
    && mkdir -p /opt/veridict/guest \
    && chown -R veridict:veridict /opt/veridict

COPY --chown=veridict:veridict shared/ /opt/veridict/shared/
COPY --chown=veridict:veridict guest/scan_url.py /opt/veridict/guest/scan_url.py
COPY --chown=veridict:veridict guest/rea_observer.py /opt/veridict/guest/rea_observer.py
COPY --chown=veridict:veridict guest/scan_email.py /opt/veridict/guest/scan_email.py
COPY --chown=veridict:veridict LICENSE /opt/veridict/LICENSE
COPY --chown=veridict:veridict THIRD_PARTY_NOTICES.md /opt/veridict/THIRD_PARTY_NOTICES.md

USER veridict
WORKDIR /opt/veridict
CMD ["sleep", "infinity"]
