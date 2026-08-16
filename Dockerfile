FROM python:3.12-slim
WORKDIR /app
COPY . /app
ENV PYTHONUNBUFFERED=1
ENV ADF_LEDGER=/data/action_ledger.jsonl
VOLUME ["/data"]
EXPOSE 8080
CMD ["python3", "-m", "adf", "serve", "--host", "0.0.0.0", "--port", "8080"]
