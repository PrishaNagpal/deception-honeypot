FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates ./templates
COPY static ./static

ENV PYTHONUNBUFFERED=1
ENV PORT=80
EXPOSE 80

CMD ["gunicorn", "--bind", "0.0.0.0:80", "--access-logfile", "-", "app:app"]
