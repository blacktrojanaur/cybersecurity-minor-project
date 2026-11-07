FROM python:3.11-slim
WORKDIR /app
COPY m5_ml/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY common/ ./common/
COPY m5_ml/ ./m5_ml/
RUN mkdir -p testbed/data
# Create models dir (populated by `make train` via volume mount)
RUN mkdir -p m5_ml/models
WORKDIR /app
ENV PYTHONPATH=/app
EXPOSE 8005
CMD ["uvicorn", "m5_ml.main:app", "--host", "0.0.0.0", "--port", "8005"]
