FROM python:3.11.9-slim-bookworm

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

# app.db is intentionally NOT copied: it is generated at runtime by db.py.
COPY app.py auth.py db.py config.yaml ./

# Bind the container to all interfaces so the service is reachable from the host.
RUN sed -i 's/host: "127.0.0.1"/host: "0.0.0.0"/' config.yaml

RUN useradd --create-home --shell /usr/sbin/nologin appuser && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

# Initialize the SQLite database on startup, then launch the app.
CMD ["sh", "-c", "python db.py && python app.py"]