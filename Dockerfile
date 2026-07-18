FROM golang:1.25-alpine AS nuclei-builder
RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

FROM python:3.12-slim
COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei
RUN nuclei -update-templates -silent || true
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .
COPY app/ ./app/
EXPOSE 8008
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8008"]
