# AISM orchestrator stub (S3) – minimal prototype image.
# Build context: repository root. Reproducible build: see gateway/Dockerfile and README.
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    POLICY_PATH=/etc/aism/policy/policy.yaml \
    POLICY_SCHEMA_PATH=/app/policy.schema.json \
    LISTEN=0.0.0.0:9000

WORKDIR /app
COPY orchestrator/requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --no-compile --require-hashes --no-deps -r requirements.lock
COPY policy/policy.schema.json /app/policy.schema.json
COPY orchestrator/aism_orchestrator /app/aism_orchestrator
USER 10001:10001
EXPOSE 9000
CMD ["python", "-m", "aism_orchestrator"]
