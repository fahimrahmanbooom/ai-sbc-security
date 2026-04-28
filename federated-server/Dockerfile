FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.111.0 uvicorn[standard]==0.29.0 numpy==1.26.4 aiohttp==3.9.5

COPY main.py .

RUN mkdir -p /data

EXPOSE 8765

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8765", "--log-level", "info"]
