FROM ubuntu:22.04

# Install gunicorn, python and sqlite
RUN apt-get update && apt-get install -y gunicorn python3 python3-pip sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Copy the flag (644 = world-readable so non-root can read it)
COPY ./flag/flag /flag
RUN chmod 644 /flag

RUN mkdir /tmp/app

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY ./src/app .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port the app runs on
EXPOSE 8862

# Copy a script to initialize the database and start gunicorn
COPY src/serve.sh /usr/src/app
RUN chmod +x /usr/src/app/serve.sh

# Create non-root user for running the web server
RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /usr/src/app && \
    chown appuser:appuser /tmp/app

USER appuser

# Start gunicorn and the Flask app
CMD ["./serve.sh"]
