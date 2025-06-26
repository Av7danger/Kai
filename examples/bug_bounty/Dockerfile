# Enhanced Bug Bounty Framework - Production Dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    # Basic system tools
    wget \
    curl \
    git \
    unzip \
    # Build dependencies
    build-essential \
    gcc \
    # Network tools
    dnsutils \
    netcat-traditional \
    nmap \
    # Clean up
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for many security tools)
RUN wget https://golang.org/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz

# Set Go environment
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin
ENV GOPATH=/root/go

# Install security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/OWASP/Amass/v4/...@master

# Update nuclei templates
RUN nuclei -update-templates

# Copy Python requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs \
    && mkdir -p /app/reports \
    && mkdir -p /app/data \
    && mkdir -p /app/temp

# Set permissions
RUN chmod +x /app/*.py

# Create non-root user for security
RUN useradd -m -u 1000 scanner \
    && chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Expose ports
EXPOSE 8000 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["python", "-m", "enhanced_integration"]
