FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates ./templates
COPY static ./static

# Unprivileged user. UID 1000 matches the host owner of ./data/flask so the
# bind-mounted log stays writable.
RUN useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin honeypot \
 && mkdir -p /var/log/honeypot \
 && chown honeypot:honeypot /var/log/honeypot

ENV PYTHONUNBUFFERED=1
ENV PORT=8080
EXPOSE 8080

USER honeypot

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--access-logfile", "-", "app:app"]
