FROM gcc

RUN apt-get update -y \
    && apt-get install --no-install-recommends -y xinetd python3 curl unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install codeql
RUN curl -L https://github.com/github/codeql-cli-binaries/releases/download/v2.21.1/codeql-linux64.zip -o codeql.zip && \
    unzip codeql.zip && \
    mv codeql /opt/codeql && \
    ln -s /opt/codeql/codeql /usr/local/bin/codeql && \
    rm codeql.zip

# Create the flag
COPY flag/flag /flag
RUN chmod 644 /flag

RUN useradd -u 31337 -ms /bin/bash challenge
RUN chown challenge:challenge /home/challenge
RUN chmod 755 /home/challenge

# Source files
COPY src /home/challenge/src
RUN chown -R challenge:challenge /home/challenge/src

# Read-only files
COPY ro /home/challenge/ro
RUN chmod 755 /home/challenge/ro
RUN chown -R challenge:challenge /home/challenge/ro

# Writeable files
COPY rw /home/challenge/rw
RUN chmod 755 /home/challenge/rw
RUN chown -R challenge:challenge /home/challenge/rw

# Installs the depedencies (as root)
USER challenge
WORKDIR /home/challenge/rw
RUN codeql pack install

# Creates the application
WORKDIR /home/challenge/src
RUN make
RUN cp -R codequill-db /home/challenge/rw/
RUN cp codequill.c /home/challenge/ro/
RUN cp codequill.py /home/challenge/ro/
RUN cp service.sh /home/challenge/ro/service.sh
RUN chmod 755 /home/challenge/ro/service.sh

USER root
# Install the service
RUN cp xinetd.conf /etc/xinetd.d/codequill

# The port this leaves on
EXPOSE 12667
CMD ["/usr/sbin/xinetd", "-dontfork"]
