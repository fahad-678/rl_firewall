FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    iptables \
    libpcap-dev \
    libnetfilter-queue-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

COPY . .

CMD ["python","-u","main.py"]