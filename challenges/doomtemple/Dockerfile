FROM ubuntu:22.04

#FROM python:3.9-slim
#WORKDIR /app
#COPY app.py flag.txt requirements.txt /app/
#COPY templates/ /app/templates/
#RUN pip install -r requirements.txt

# Install gunicorn, python and sqlite
RUN apt-get update && apt-get install -y gunicorn python3 python3-pip sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Copy the flag
COPY ./flag/flag /flag
RUN chmod 644 /flag

RUN mkdir /tmp/app; chmod 755 /tmp/app

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY ./src/app .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port the app runs on
EXPOSE 1526

# Copy a script to initialize the database and start MySQL
COPY src/serve.sh /usr/src/app
RUN chmod +x /usr/src/app/serve.sh

# Start gunicorn and the Flask app
CMD ["./serve.sh"]
