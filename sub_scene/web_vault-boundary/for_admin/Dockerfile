FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/app/
COPY private/ /app/private/

RUN groupadd --system --gid 10001 vault && \
    useradd --system --uid 10001 --gid vault --no-create-home vault

USER vault

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4", "--limit-concurrency", "256", "--timeout-keep-alive", "5", "--no-access-log"]
