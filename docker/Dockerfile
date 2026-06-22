FROM python:3.14-alpine

COPY ../porkcron.py /usr/local/bin/porkcron
RUN chmod +x /usr/local/bin/porkcron

COPY crontab /etc/crontabs/root

CMD [ "crond", "-f" ]
