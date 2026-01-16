FROM ubuntu:22.04

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 31337 -ms /bin/bash challenge
# Prevents the user from writing to the home directory
RUN chown root:root /home/challenge
RUN chmod 755 /home/challenge

COPY flag/flag /flag
RUN chmod 644 /flag

# Source files (includes the prebuilt firmware binary)
COPY src /home/challenge/src
# Read-only files
COPY ro /home/challenge/ro
RUN cp /home/challenge/src/extrafirm /home/challenge/ro/extrafirm
RUN chmod 755 /home/challenge/ro/extrafirm

# Writeable files
COPY rw /home/challenge/rw
RUN chown challenge:challenge /home/challenge/rw
RUN chmod 755 /home/challenge/rw

# Install the service
COPY src/xinetd.conf /etc/xinetd.d/extrafirm

# The port this leaves on
EXPOSE 28652
CMD ["/usr/sbin/xinetd", "-dontfork"]
