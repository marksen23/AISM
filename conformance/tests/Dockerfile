# AISM conformance tools image (test runner + mock IdP). Build context: repository root.
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY conformance/tests/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt PyJWT==2.15.1
WORKDIR /repo/conformance/tests
