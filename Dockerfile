FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DJANGO_SETTINGS_MODULE=svc.settings

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium

COPY . .

EXPOSE 8000
# 啟動時 lifespan 會完成 Django setup 並建表（SQLite 暫存）
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
