FROM ubuntu:24.04

RUN useradd -m -u 1001 ctf
WORKDIR /home/ctf
COPY bin/archive-sweeper /home/ctf/archive-sweeper
COPY assets/ /home/ctf/template/
COPY flag.txt /home/ctf/flag

RUN chown -R root:ctf /home/ctf \
    && chmod 0555 /home/ctf/archive-sweeper \
    && find /home/ctf/template -type d -exec chmod 0555 {} + \
    && find /home/ctf/template -type f -exec chmod 0444 {} + \
    && chmod 0444 /home/ctf/flag

USER ctf
EXPOSE 31344
CMD ["/home/ctf/archive-sweeper"]
