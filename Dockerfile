FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY deploy/vm/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 winkey \
    && useradd --uid 10001 --gid 10001 --no-create-home winkey \
    && mkdir /data /updates && chown 10001:10001 /data
COPY deploy/gateway_production_server.py /app/deploy/gateway_production_server.py
COPY deploy/vm/server.py /app/server.py
USER 10001:10001
EXPOSE 8788
CMD ["python", "server.py"]
