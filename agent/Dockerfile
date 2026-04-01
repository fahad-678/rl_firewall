FROM python:3.10-slim

# Install system dependencies required for packet manipulation
RUN apt-get update && apt-get install -y \
    build-essential \
    iptables \
    libnetfilter-queue-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Container must run as root with NET_ADMIN capabilities
CMD ["python", "main.py"]