FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    socat coreutils curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1001 ctf

WORKDIR /home/ctf
COPY bin/framevault /home/ctf/framevault
COPY ["[[]Deleted]", "/home/ctf/[Deleted]/"]

RUN chown -R root:ctf /home/ctf \
    && chmod 0555 /home/ctf/framevault \
    && chmod -R a=rX "/home/ctf/[Deleted]"

USER ctf
EXPOSE 31342

CMD ["socat", "TCP-LISTEN:31342,reuseaddr,fork,max-children=64", "EXEC:timeout 300 /home/ctf/framevault,stderr"]
