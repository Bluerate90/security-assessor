# ============================================================================
# Dockerfile
# Place in: security_assessor/docker/Dockerfile
# Build from security_assessor folder: docker build -f docker/Dockerfile .
# ============================================================================

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration files
COPY Configuration/ ./Configuration/

# Copy Python backend modules
COPY Python-Modules-Backend/ ./Python-Modules-Backend/

# Copy HTML frontend file
COPY index.html ./

# Copy the main web server
COPY web_server.py ./

# Install Python dependencies
RUN pip install --no-cache-dir -r Configuration/requirements.txt

# Create necessary directories
RUN mkdir -p ./logs ./Runtime/assessor_cache

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Run the application
CMD ["python", "web_server.py"]