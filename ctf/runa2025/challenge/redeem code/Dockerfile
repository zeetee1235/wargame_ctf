FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLAG_PATH=/app/flag

WORKDIR /app

RUN pip install --upgrade pip && \
    pip install \
      Flask==3.0.2 \
      bcrypt==4.1.2 \
      gunicorn==21.2.0

# 앱/정적파일 복사
COPY app.py /app/
COPY templates /app/templates
COPY static /app/static

COPY flag /app/flag
RUN chmod 0444 /app/flag

EXPOSE 6001

# 비루트
USER 10001

CMD ["gunicorn", "-w", "2", "-k", "gthread", "--threads", "8", "-b", "0.0.0.0:6001", "app:app"]
