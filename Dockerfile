# tether server image: owns the files, the audit key and both servers.
FROM python:3.12-slim

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin tether \
 && mkdir -p /data /keys \
 && chown tether:tether /data /keys && chmod 700 /keys

# tether has no dependencies, so the image needs no network at build time:
# copy the package in and add a launcher.
COPY tether /opt/tether/tether
RUN printf '#!/bin/sh\nexec python -m tether "$@"\n' > /usr/local/bin/tether && chmod 755 /usr/local/bin/tether
ENV PYTHONPATH=/opt/tether

COPY docker/entrypoint.sh /usr/local/bin/tether-entrypoint
RUN chmod 755 /usr/local/bin/tether-entrypoint

USER tether
ENV TETHER_ROOT=/data/drive \
    TETHER_AUDIT_KEY_FILE=/keys/audit.key \
    PYTHONUNBUFFERED=1
VOLUME ["/data", "/keys"]
EXPOSE 8700 8701
ENTRYPOINT ["tether-entrypoint"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8700", "--allowed-host", "localhost:8700", "--allowed-host", "127.0.0.1:8700"]
