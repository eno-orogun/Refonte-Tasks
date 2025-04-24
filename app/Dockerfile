# Use the official Python base image
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    clang \
    meson \
    python3-dev \
    libdbus-1-dev

# Set the working directory
WORKDIR /app

# Copy the requirements.txt file into the container
COPY app/requirements.txt /app/

RUN pip install --upgrade pip

# Install the necessary dependencies
#RUN pip install -r requirements.txt

# Explicitly install Flask just in case
RUN pip install Flask==3.0.2  

# Copy the rest of the application into the container
COPY . /app/

# Expose the port Flask app will run on (default is 5000)
EXPOSE 5000

# Set the environment variable for Flask to run in production mode
ENV FLASK_ENV=production

# Command to run the Flask app
CMD ["python", "app.py"]
