# Use a lightweight Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port FastAPI will run on
EXPOSE 8000

# Command to run the application
# We use 0.0.0.0 to allow external connections (from Vercel)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
