FROM python:3.13-slim
WORKDIR /app
COPY app ./app
COPY config ./config
COPY data/demo_records.json data/demo_assets.json ./data/
COPY web ./web
RUN mkdir -p /app/data && useradd --uid 10001 --create-home zhidun && chown -R zhidun:zhidun /app/data
USER zhidun
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health',timeout=2)" || exit 1
CMD ["python", "-m", "app.server", "--host", "0.0.0.0"]
