FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8443 8501
CMD ["python", "-m", "sensetrust.server", "--data", "/data", "--host", "0.0.0.0"]
