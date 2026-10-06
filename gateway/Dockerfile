# AISM governance gateway (S2) – prototype image.
# Build context: repository root (docker-compose.yml: build.context ".", dockerfile gateway/Dockerfile)
# Reproducible build (README "Reproduzierbare Builds"): base image pinned by digest, all Python
# dependencies pinned with hashes (requirements.lock, pip-compile --generate-hashes), no .pyc files
# (pip --no-compile, PYTHONDONTWRITEBYTECODE), no useradd (numeric UID, no /etc/shadow timestamp).
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    POLICY_PATH=/etc/aism/policy/policy.yaml \
    POLICY_SCHEMA_PATH=/app/policy.schema.json \
    AUDIT_LOG_PATH=/audit/audit.jsonl

WORKDIR /app
COPY gateway/requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --no-compile --require-hashes --no-deps -r requirements.lock

COPY policy/policy.schema.json /app/policy.schema.json
COPY gateway/aism_gateway /app/aism_gateway

# Optional GLiNER cascade. The default build (INSTALL_GLINER=0) does not install torch and stays
# on the hash-locked requirements.lock above. The variant is not part of the reproducible image:
#   docker build --build-arg INSTALL_GLINER=1 -f gateway/Dockerfile .
# It prefetches urchade/gliner_multi_pii-v1 into HF_HOME so startup does not need the network.
# A policy that sets ner.cascade still fails closed if that model cannot be loaded.
ARG INSTALL_GLINER=0
COPY gateway/requirements-gliner.txt /tmp/requirements-gliner.txt
RUN mkdir -p /opt/hf && chown 10001:10001 /opt/hf
ENV HF_HOME=/opt/hf
RUN if [ "$INSTALL_GLINER" = "1" ]; then \
      pip install --no-cache-dir --no-compile -r /tmp/requirements-gliner.txt && \
      python -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_multi_pii-v1')" && \
      chown -R 10001:10001 /opt/hf; \
    fi

RUN mkdir -p /audit && chown 10001:10001 /audit
USER 10001:10001
EXPOSE 8000 8001
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4).status==200 else 1)"
CMD ["python", "-m", "aism_gateway"]
