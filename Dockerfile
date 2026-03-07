# UNetDefence API container
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY requirements.txt .

RUN pip install --no-cache-dir -e .

ENV UNETDEFENCE_DATABASE_URL=postgresql://localhost/unetdefence
EXPOSE 8000

CMD ["uvicorn", "unetdefence.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
