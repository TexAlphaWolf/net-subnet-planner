FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[web]" \
    && useradd --system --no-create-home --uid 10001 subnetplan \
    && install -d -o subnetplan /data

# The database lives in /data. Root is not needed and the root filesystem can be read-only.
# There is no authentication: publish the port on the loopback interface only, e.g.
#   docker run -p 127.0.0.1:8080:8080 -v subnetplan:/data subnetplan
USER subnetplan
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/api/audit', timeout=2)"
ENTRYPOINT ["subnetplan"]
CMD ["serve", "--db", "/data/ipam.db", "--host", "0.0.0.0", "--port", "8080"]
