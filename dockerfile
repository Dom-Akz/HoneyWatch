FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir flask flask-cors requests paramiko scapy pandas numpy scikit-learn joblib

# Copy the rest of the application
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY scripts/ ./scripts/
COPY data/ ./data/
COPY models/ ./models/

EXPOSE 8000
