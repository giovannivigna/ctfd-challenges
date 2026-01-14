FROM ubuntu:22.04

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd build-essential libelf-dev binutils ca-certificates python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY ./flag/flag /flag
RUN chmod 644 /flag

RUN useradd -u 31337 -ms /bin/bash challenge
# Prevents the user from writing to the home directory
RUN chown root:root /home/challenge
RUN chmod 755 /home/challenge

# Source files
COPY src /home/challenge/src
# Read-only files
COPY ro /home/challenge/ro
# Writeable files
COPY rw /home/challenge/rw
RUN chown challenge:challenge /home/challenge/rw
RUN chmod 755 /home/challenge/rw

# Build binaries
WORKDIR /home/challenge/src
RUN make

# Install executables to read-only directory
RUN cp sample /home/challenge/ro/sample \
    && chmod 755 /home/challenge/ro/sample \
    && cp /home/challenge/src/cinfra_patcher.py /home/challenge/ro/cinfra_patcher.py \
    && chmod 755 /home/challenge/ro/cinfra_patcher.py

# Install the service
RUN mv /home/challenge/src/xinetd.conf /etc/xinetd.d/c-section

EXPOSE 31339
CMD ["/usr/sbin/xinetd", "-dontfork"]
