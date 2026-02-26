FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container
COPY ./src/app /app

# Copy the flag where the app expects it
COPY ./flag/flag /flag
RUN chmod 444 /flag

# Install Flask
RUN pip install --no-cache-dir flask

# Expose port 5000 for the app
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]
