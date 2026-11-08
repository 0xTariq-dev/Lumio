FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONPATH=/opt/veridict

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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
COPY --chown=veridict:veridict LICENSE /opt/veridict/LICENSE
COPY --chown=veridict:veridict THIRD_PARTY_NOTICES.md /opt/veridict/THIRD_PARTY_NOTICES.md

USER veridict
WORKDIR /opt/veridict
CMD ["sleep", "infinity"]
