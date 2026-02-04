FROM gcc

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Register the service name/port so xinetd listens on it.
RUN printf "cookiemonster\\t5004/tcp\\n" >> /etc/services

COPY flag/flag /flag
RUN chmod 644 /flag
RUN chown root:root /flag

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
RUN cp cookiemonster /home/challenge/ro/cookiemonster
RUN chmod 755 /home/challenge/ro/cookiemonster
RUN cp service.sh /home/challenge/ro/service.sh
RUN chmod 755 /home/challenge/ro/service.sh

# Install the service
RUN cp xinetd.conf /etc/xinetd.d/cookiemonster

# The port this leaves on
EXPOSE 5004
CMD ["/usr/sbin/xinetd", "-dontfork"]

