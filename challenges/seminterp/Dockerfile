FROM python:3.11-slim

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir semgrep

COPY flag/flag /flag
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
RUN chown -R challenge:challenge /home/challenge/rw
RUN chmod 755 /home/challenge/rw

RUN cp /home/challenge/src/seminterp.py /home/challenge/ro/seminterp.py \
    && cp /home/challenge/src/service.sh /home/challenge/ro/service.sh \
    && chmod 755 /home/challenge/ro/service.sh

# Install the service
RUN cp /home/challenge/src/xinetd.conf /etc/xinetd.d/seminterp

# The port this leaves on
EXPOSE 31342
CMD ["/usr/sbin/xinetd", "-dontfork"]
