# Use a lightweight Python base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to leverage Docker's cache
COPY requirements.txt .

# Install all project dependencies (Flask, Gemini, Web3, etc.)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . .

# Expose the port your Flask app uses
EXPOSE 5000

# Command to run your application
# Ensure 'app.py' is your main entry point as seen in your project files
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]