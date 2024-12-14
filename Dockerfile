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

# Set environment variables if needed (optional)
# ENV JWT_SECRET_KEY=your_jwt_secret_key
# ENV SECRET_KEY=your_secret_key
# and so on...
# Or rely on an .env file mounted at runtime and python-dotenv to load it.

# Run the Flask application
CMD ["python", "main.py"]