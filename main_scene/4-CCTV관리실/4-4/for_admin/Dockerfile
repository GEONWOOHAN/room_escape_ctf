FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1001 ctf
WORKDIR /home/ctf
COPY bin/archive-sweeper /home/ctf/archive-sweeper
COPY ctfd_auth.py /home/ctf/ctfd_auth.py
COPY assets/ /home/ctf/template/
COPY flag.txt /home/ctf/flag

RUN chown -R root:ctf /home/ctf \
    && mkdir -p /data && chown ctf:ctf /data \
    && chmod 0555 /home/ctf/archive-sweeper \
    && chmod 0444 /home/ctf/ctfd_auth.py \
    && find /home/ctf/template -type d -exec chmod 0555 {} + \
    && find /home/ctf/template -type f -exec chmod 0444 {} + \
    && chmod 0444 /home/ctf/flag

USER ctf
EXPOSE 31344
CMD ["/home/ctf/archive-sweeper"]
