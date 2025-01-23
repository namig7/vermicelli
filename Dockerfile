# 1) Builder Stage
FROM python:3.10-slim AS builder

# Workdir inside the builder image
WORKDIR /app

# Copy only the requirements first, so Docker can cache this step
COPY requirements.txt .

# Install build dependencies, then install Python packages
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get remove -y gcc && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# 2) Final Stage
FROM python:3.10-slim

WORKDIR /app

# Copy installed Python libraries from the builder stage
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages

# Now copy the rest of your application code (including main.py)
COPY . .

# Expose the Flask port
EXPOSE 8000

# Final command to run the Flask app
CMD ["python", "main.py"]