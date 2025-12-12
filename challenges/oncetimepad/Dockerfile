FROM python

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 31337 -ms /bin/bash challenge
# Prevents the user from writing to the home directory
RUN chown root:root /home/challenge
RUN chmod 755 /home/challenge

COPY flag/flag.txt /flag.txt
RUN chmod 644 /flag.txt

# Source files
COPY src /home/challenge/src
# Read-only files
COPY ro /home/challenge/ro
RUN cp /home/challenge/src/oncetimepad.py /home/challenge/ro/oncetimepad.py
RUN chmod 755 /home/challenge/ro/oncetimepad.py

# Writeable files
COPY rw /home/challenge/rw
RUN chown challenge:challenge /home/challenge/rw
RUN chmod 755 /home/challenge/rw

# Install the service
COPY src/xinetd.conf /etc/xinetd.d/oncetimepad

# The port this leaves on
EXPOSE 7788
CMD ["/usr/sbin/xinetd", "-dontfork"]
