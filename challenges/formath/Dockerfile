FROM ubuntu:20.04

RUN dpkg --add-architecture i386 \
    && apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd make gcc-multilib g++-multilib libc6-dev-i386 libssl-dev:i386 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY flag/flag.txt /flag.txt
RUN chmod 644 /flag.txt

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

# Creates the application
WORKDIR /home/challenge/src 
RUN make
RUN cp formath /home/challenge/ro/
RUN cp service.sh /home/challenge/ro/
RUN chmod 755 /home/challenge/ro/service.sh

# Install the service
RUN cp xinetd.conf /etc/xinetd.d/formath

# The port this leaves on
EXPOSE 1108
CMD ["/usr/sbin/xinetd", "-dontfork"]

# docker build .
# docker run -d -p 1108:1108 --name formath <image id>
