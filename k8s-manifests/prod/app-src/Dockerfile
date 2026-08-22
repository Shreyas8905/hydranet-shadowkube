FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask requests
WORKDIR /app
COPY frontend.py backend.py keystore.py /app/
# ENTRYPOINT chosen at deploy time via k8s manifest `command:` field,
# so a single image serves all three roles.
