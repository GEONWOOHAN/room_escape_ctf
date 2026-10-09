FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY ctfd_auth.py .
COPY agent_runtime.py .
COPY manage.py .
COPY static ./static

RUN useradd --create-home --uid 10001 botficial && mkdir -p /data && chown botficial:botficial /data
USER botficial
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
