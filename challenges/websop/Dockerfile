FROM python:3.11-slim

WORKDIR /usr/src/app

COPY ./flag/flag /flag
RUN chmod 444 /flag

COPY ./src/app /usr/src/app
COPY ./ro/vuln_app.py /usr/src/app/vuln_app.py

RUN pip install --no-cache-dir flask gunicorn

EXPOSE 8863

COPY src/serve.sh /usr/src/app/serve.sh
RUN chmod +x /usr/src/app/serve.sh

CMD ["./serve.sh"]

