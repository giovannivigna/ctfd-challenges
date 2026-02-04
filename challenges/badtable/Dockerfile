FROM ubuntu:20.04

RUN dpkg --add-architecture i386 \
    && apt-get update -y \
    && apt-get install --no-install-recommends -y \
    wget \
    python3 \
    gdb \
    vim \
    file \
    locales \
    xinetd \
    make \
    gcc-multilib g++-multilib \
    libc6-dev-i386 libssl-dev:i386 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Generate en_US.UTF-8 locale
RUN locale-gen en_US.UTF-8

# Set environment variables to use the generated locale
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Install GEF - the || true at the end is to make sure that the command returns 0 (otherwise returns 5)
# RUN bash -c "$(wget --no-check-certificate https://gef.blah.cat/sh -O -)" || true
RUN wget -O ~/.gdbinit-gef.py --no-check-certificate https://gef.blah.cat/py
RUN echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# Flag must not be /flag.txt (see FORMAT.md)
COPY flag/flag /flag
RUN chmod 644 /flag && chown root:root /flag

RUN useradd -u 31337 -ms /bin/bash challenge
# Prevents the user from writing to the home directory
RUN chown root:root /home/challenge
RUN chmod 755 /home/challenge

# Source files
COPY src/badtable.c /home/challenge/src/badtable.c
# Read-only files
COPY ro /home/challenge/ro
# Writeable files
COPY rw /home/challenge/rw
RUN chown challenge:challenge /home/challenge/rw
RUN chmod 755 /home/challenge/rw

# Creates the application
COPY src/Makefile /home/challenge/src/Makefile
WORKDIR /home/challenge/src
RUN make
RUN cp badtable /home/challenge/ro/badtable
COPY src/service.sh /home/challenge/ro/service.sh
RUN chmod 755 /home/challenge/ro/service.sh

# Install the service
COPY src/xinetd.conf /etc/xinetd.d/badtable

# The port this leaves on
EXPOSE 1104
CMD ["/usr/sbin/xinetd", "-dontfork"]

# docker build .
# docker run -d -p 1104:1104 --name badtable <image id>
