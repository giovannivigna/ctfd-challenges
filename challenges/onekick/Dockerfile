FROM gcc

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

# Build the binary
WORKDIR /home/challenge/src
RUN make clean && make

# Install the binary and service script
RUN cp onekick /home/challenge/ro/onekick
RUN cp service.sh /home/challenge/ro/service.sh
RUN chmod 755 /home/challenge/ro/onekick
RUN chmod 755 /home/challenge/ro/service.sh

# Writeable files
COPY rw /home/challenge/rw
RUN chown challenge:challenge /home/challenge/rw
RUN chmod 755 /home/challenge/rw

# Install the service
COPY src/xinetd.conf /etc/xinetd.d/onekick

# The port this leaves on
EXPOSE 7779
CMD ["/usr/sbin/xinetd", "-dontfork"]
