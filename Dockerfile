FROM python:3.11-slim

LABEL maintainer="training"
LABEL description="Deliberately vulnerable MCP server for security education — DO NOT USE IN PRODUCTION"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir \
    "mcp[cli]>=1.0.0" \
    "pydantic>=2.0.0" \
    "pydantic-settings>=2.0.0" \
    "httpx>=0.24.0" \
    "pyyaml>=6.0" \
    "jinja2>=3.0.0" \
    "uvicorn>=0.20.0"

# Copy project files
COPY . .

# Safety: training mode required by default
# Sandbox mode on by default — set MCP_SANDBOX=false only for advanced demos
ENV MCP_TRAINING_MODE=true
ENV MCP_SANDBOX=true
ENV MCP_TRANSPORT=sse
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000
ENV MCP_DIFFICULTY=all

# Create a non-root training user to limit blast radius
RUN useradd -m -s /bin/bash training && chown -R training:training /app
USER training

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

CMD ["python", "server.py"]
