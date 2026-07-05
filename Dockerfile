FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py auth.py db.py config.yaml app.db ./

# Keep the container-local config aligned with the host port from config.yaml
# so DAST can reach the service on 0.0.0.0:5000.
RUN sed -i 's/host: "127.0.0.1"/host: "0.0.0.0"/' config.yaml

# Trivy and Checkov will flag the image for running as root; we leave that
# intact on purpose so the scan target stays interesting.
EXPOSE 5000

CMD ["python", "app.py"]
