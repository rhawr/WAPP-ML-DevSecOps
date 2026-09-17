# Build context = repository root:  docker build -f app/Dockerfile -t taller-waap/app .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RASP_ENABLED=true \
    PORT=5000

WORKDIR /srv

COPY app/requirements.txt app/requirements.txt
RUN pip install --no-cache-dir -r app/requirements.txt

COPY observability observability
COPY app app

EXPOSE 5000

CMD ["python", "app/vulnerable_app.py"]
