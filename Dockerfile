# 1) Builder Stage
ARG PYTHON_VERSION=3.14.5
FROM python:${PYTHON_VERSION}-slim AS builder

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
FROM python:${PYTHON_VERSION}-slim

WORKDIR /app

# Copy installed Python libraries from the builder stage
COPY --from=builder /usr/local /usr/local

# Now copy the rest of your application code (including main.py)
COPY . .

# Expose the Flask port
EXPOSE 8000

# Final command to run the Flask app
CMD ["python", "main.py"]
