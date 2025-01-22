########################
# 1) Builder Stage
########################
FROM python:3.10-slim as builder

WORKDIR /app

# Install build dependencies (e.g. gcc) here
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get remove -y gcc && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first
COPY requirements.txt .

# Install packages into a temporary folder (/install)
# Using --target or --prefix to install them in an isolated directory
RUN pip install --no-cache-dir -r requirements.txt --target /install

########################
# 2) Final Stage
########################
FROM python:3.10-slim

WORKDIR /app

# Copy installed Python packages from the builder stage
COPY --from=builder /install /usr/local/lib/python3.10/site-packages

# Copy your application code
COPY . .

# Expose the port used by Flask
EXPOSE 8000

CMD ["python", "main.py"]