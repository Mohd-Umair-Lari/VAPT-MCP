# Dockerfile for VAPT Agent
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy project
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir requests

# Create non-root user
RUN useradd -m -u 1000 vapt && chown -R vapt:vapt /app
USER vapt

# Entry point
ENTRYPOINT ["python"]

# Default command shows help
CMD ["vapt_mvp.py", "--help"]