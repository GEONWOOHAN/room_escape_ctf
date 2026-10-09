FROM python:3.12-slim
WORKDIR /app
COPY challenge/ /app/challenge/
COPY private/ /app/private/
RUN groupadd --system --gid 10002 bloom && \
    useradd --system --uid 10002 --gid bloom --no-create-home bloom && \
    mkdir -p /data && chown 10002:10002 /data && \
    chown -R root:root /app
USER bloom
EXPOSE 8080
CMD ["python3", "-m", "challenge.server"]
