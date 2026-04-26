FROM python:3.11-slim-bookworm

LABEL maintainer="AI SBC Security Project"
LABEL description="AI-powered security monitoring for Single Board Computers"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpcap-dev \
    gcc \
    g++ \
    nodejs \
    npm \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Build frontend
COPY frontend/package.json frontend/
WORKDIR /app/frontend
RUN npm install && npm run build
WORKDIR /app

# Copy backend
COPY backend/ ./backend/
COPY config/ ./config/

# Copy built frontend into backend static folder
RUN cp -r frontend/dist backend/static

# Set capabilities for packet capture without root
RUN setcap cap_net_raw+ep $(which python3) || true

# Create data directory
RUN mkdir -p /var/lib/ai-sbc-security

EXPOSE 8080

CMD ["python3", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
