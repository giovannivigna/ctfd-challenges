FROM python

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd \
    nasm \
    gcc \
    libc6-dev \
    python3 \
    python3-pip \
    socat \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install pwntools
RUN pip3 install pwntools

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
RUN cp /home/challenge/src/assemblex /home/challenge/ro/assemblex
RUN chmod 755 /home/challenge/ro/assemblex

# Writeable files
COPY rw /home/challenge/rw
RUN chown challenge:challenge /home/challenge/rw
RUN chmod 755 /home/challenge/rw

# Install the service
COPY src/xinetd.conf /etc/xinetd.d/assemblex

# The port this leaves on
EXPOSE 36363
CMD ["/usr/sbin/xinetd", "-dontfork"]
