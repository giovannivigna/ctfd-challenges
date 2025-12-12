FROM ubuntu:latest

# Install gunicorn sqlite and python 
RUN apt-get update && apt-get install -y gunicorn python3 python3-pip sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY ./src/app .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Create the database
RUN python3 database.py

# Expose the port the app runs on
EXPOSE 8443

# Copy a script to initialize the database and start MySQL
COPY src/serve.sh /usr/src/app
RUN chmod +x /usr/src/app/serve.sh

# Start gunicorn and the Flask app
CMD ["./serve.sh"]
