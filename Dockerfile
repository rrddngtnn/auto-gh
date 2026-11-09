FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY packages ./packages

RUN pip install --no-cache-dir -e . \
    && mkdir -p /data

ENTRYPOINT ["auto-gh"]
CMD ["status"]
