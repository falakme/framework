# The scan job's image. The worker runs it as an unprivileged user with no network.
FROM python:3.12-slim
COPY scan.py /app/scan.py
USER 65534:65534
