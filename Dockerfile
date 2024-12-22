# Use a lightweight base image with Python 3
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port your Flask app runs on (default: 8000)
EXPOSE 8000

# Run the Flask application
CMD ["python", "main.py"]