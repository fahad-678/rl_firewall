FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    iptables \
    libnetfilter-queue-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python","-u","main.py"]