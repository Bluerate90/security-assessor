FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y gcc curl && rm -rf /var/lib/apt/lists/*

# Copy files
COPY Configuration/ ./Configuration/
COPY Python-Modules-Backend/ ./Python-Modules-Backend/
COPY index.html ./
COPY web_server.py ./

# Install requirements FIRST (before running app)
RUN pip install --no-cache-dir -r Configuration/requirements.txt

# Create directories
RUN mkdir -p ./logs ./Runtime/assessor_cache

# Expose port
EXPOSE 8080

# Set environment
ENV PORT=8080

# Run app
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "web_server:app"]