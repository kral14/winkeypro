FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY deploy/vm/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 winkey \
    && useradd --uid 10001 --gid 10001 --no-create-home winkey \
    && mkdir /data /updates && chown 10001:10001 /data /updates
COPY deploy/gateway_production_server.py deploy/gateway_service.py deploy/asgi_app.py deploy/websocket_hub.py deploy/postgres_database.py deploy/update_repository.py /app/deploy/
COPY deploy/vm/server.py /app/server.py
COPY deploy/vm/dashboard.html /app/dashboard.html
USER 10001:10001
EXPOSE 8788
VOLUME ["/data", "/updates"]
CMD ["python", "server.py"]
