FROM ubuntu:26.04@sha256:42527649dbc4f9197a6073f426f488cbff0e9cc9f2afce32d91c383e4875634a

RUN apt-get update \
    && apt-get install -y --no-install-recommends coreutils passwd python3 socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --user-group --create-home --shell /usr/sbin/nologin mirai

WORKDIR /home/mirai
COPY chall.py /home/mirai/chall.py
RUN chmod 0555 /home/mirai/chall.py
RUN printf '%s\n' 'QUAD26{fake}' > /flag.txt \
    && name="$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]')" \
    && mv /flag.txt "/flag_${name}.txt" \
    && chmod 0444 "/flag_${name}.txt"

USER mirai
EXPOSE 31339
CMD ["socat", "TCP-LISTEN:31339,reuseaddr,fork", "EXEC:python3 -I -B -u /home/mirai/chall.py,stderr"]
