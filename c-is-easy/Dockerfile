FROM ubuntu:26.04@sha256:42527649dbc4f9197a6073f426f488cbff0e9cc9f2afce32d91c383e4875634a

RUN apt-get update \
    && apt-get install -y --no-install-recommends busybox passwd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --user-group --create-home --shell /usr/sbin/nologin mirai

WORKDIR /home/mirai
RUN mkdir -p /www/cgi-bin
COPY chall /home/mirai/chall
COPY cgi-bin/chall /www/cgi-bin/chall
RUN printf '%s\n' 'QUAD26{fake}' > /flag.txt \
    && chmod 0444 /flag.txt \
    && chmod 0555 /home/mirai/chall /www/cgi-bin/chall

USER mirai
EXPOSE 8080
CMD ["busybox", "httpd", "-f", "-p", "8080", "-h", "/www"]
