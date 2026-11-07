FROM python:3.11-slim
WORKDIR /app
COPY testbed/mock_webhook/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY testbed/mock_webhook/ .
EXPOSE 8099
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8099"]
