# Production Dockerfile for VAPT MCP
FROM python:3.11-slim

# Install system dependencies for scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends     curl     nmap     netcat-openbsd     iputils-ping     dnsutils     whois     && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install the package in development mode
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 vapt && chown -R vapt:vapt /app
USER vapt

# Expose port for MCP server (if running HTTP mode)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3     CMD python -c "import sys; sys.path.insert(0, 'scripts'); import mcp_server; print('OK')" || exit 1

# Default command - runs MCP server via stdio (for Hermes integration)
# For HTTP mode, use: CMD ["python", "scripts/mcp_server.py", "--http", "--port", "8000"]
ENTRYPOINT ["python"]
CMD ["-m", "mcp_server"]
