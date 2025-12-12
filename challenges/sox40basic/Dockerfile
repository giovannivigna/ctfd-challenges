FROM python

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 31337 -ms /bin/bash challenge
# Prevents the user from writing to the home directory
RUN chown root:root /home/challenge
RUN chmod 755 /home/challenge

COPY flag/flag /flag
RUN chmod 644 /flag

# Source files
COPY src /home/challenge/src

# Read-only files
COPY ro /home/challenge/ro
RUN cp /home/challenge/src/sox40basic /home/challenge/ro/sox40basic
RUN chmod 755 /home/challenge/ro/sox40basic

# Install any needed packages specified in requirements.txt
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r /home/challenge/src/requirements.txt

# Writeable files
COPY rw /home/challenge/rw
RUN chown challenge:challenge /home/challenge/rw
RUN chmod 755 /home/challenge/rw

# Install the service
COPY src/xinetd.conf /etc/xinetd.d/sox40basic
# The port this leaves on
EXPOSE 11221
CMD ["/usr/sbin/xinetd", "-dontfork"]
