FROM python:3.11-slim
WORKDIR /app
# Mosquitto for the MQTT scenario (S9). SoftHSM, OpenSC and the OpenSSL PKCS#11 provider
# for tools/hsm_enrol_demo.py; optional, so a missing package does not break the build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends mosquitto \
 && (apt-get install -y --no-install-recommends softhsm2 opensc pkcs11-provider || true) \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && (pip install --no-cache-dir python-pkcs11 || true)
COPY . .
EXPOSE 8443 8444 8501
CMD ["python", "-m", "sensetrust.server", "--data", "/data", "--host", "0.0.0.0"]
