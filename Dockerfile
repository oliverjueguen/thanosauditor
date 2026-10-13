# Thanos dashboard in a container (clean install, an alternative to the venv).
#   docker build -t thanos .
#   docker run --rm -p 127.0.0.1:8000:8000 thanos      -> http://127.0.0.1:8000
# Publish the port ONLY on the host's 127.0.0.1: the dashboard has no user accounts.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    THANOS_PANEL_HOST=0.0.0.0 \
    THANOS_PANEL_PORT=8000

WORKDIR /app
COPY requirements.txt constraints.txt pyproject.toml README.md ./
COPY thanos ./thanos
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt \
 && pip install --no-cache-dir --no-deps .

COPY fixtures ./fixtures
COPY data/ontology ./data/ontology
# Thanos Auditor report (heuristic, offline) shown by the dashboard next to the score.
RUN thanos-auditor analyze "fixtures/bundles/*.bundle.json" -o output/report.json > /dev/null

# Unprivileged user.
RUN useradd --create-home --uid 10001 thanos && mkdir -p data/panel && chown -R thanos /app/data /app/output
USER thanos

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"
CMD ["thanos-panel"]
