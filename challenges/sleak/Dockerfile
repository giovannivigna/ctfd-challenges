FROM debian:bookworm-slim

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y build-essential xinetd ca-certificates procps \
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
# Read-only files (binary is installed here)
COPY ro /home/challenge/ro
# Writeable files
COPY rw /home/challenge/rw
RUN chown challenge:challenge /home/challenge/rw
RUN chmod 755 /home/challenge/rw

RUN gcc -O2 -fno-omit-frame-pointer -fPIE -pie -Wl,-z,relro,-z,now \
      -o /home/challenge/ro/sleak /home/challenge/src/sleak.c
RUN chown root:root /home/challenge/ro/sleak && chmod 755 /home/challenge/ro/sleak

# Install the service
COPY src/xinetd.conf /etc/xinetd.d/sleak

EXPOSE 9009
CMD ["/usr/sbin/xinetd", "-dontfork"]

