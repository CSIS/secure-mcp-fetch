# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install uv for fast dependency management
RUN pip install --no-cache-dir uv

# Copy requirements first for better caching
# Create a requirements.txt file from the dependencies mentioned in readme
COPY requirements.txt .

# Install Python dependencies using uv
RUN uv pip install --system --no-cache-dir -r requirements.txt

# Copy the application code
COPY main.py .
COPY LICENSE .
COPY readme.md .

# Create a non-root user for security
RUN adduser --disabled-password --gecos '' --uid 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000

# Expose the port for HTTP transport
EXPOSE 8000

# Run the application
CMD ["python", "main.py"]
