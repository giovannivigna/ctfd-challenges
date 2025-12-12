FROM ubuntu:22.04

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd build-essential gdb binutils gcc-multilib g++-multilib \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY ./flag/flag.txt /flag.txt
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

# Installs the binary
RUN cp getbuff service.sh /home/challenge/ro/
RUN chmod 755 /home/challenge/ro/service.sh
RUN chmod 755 /home/challenge/ro/getbuff

# Install the service
RUN mv /home/challenge/src/xinetd.conf /etc/xinetd.d/getbuff

# The port this leaves on
EXPOSE 28651
CMD ["/usr/sbin/xinetd", "-dontfork"]
