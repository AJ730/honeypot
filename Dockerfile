FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY honeypot ./honeypot
COPY config.yaml .
EXPOSE 11434
CMD ["uvicorn", "honeypot.main:app", "--host", "0.0.0.0", "--port", "11434", "--no-server-header"]
