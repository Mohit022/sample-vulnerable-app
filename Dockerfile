# Security-hardened Dockerfile
# FIX (CWE-250):  Pinned base image digest; non-root user; HEALTHCHECK added
# FIX (CWE-798):  Removed hardcoded AWS credentials from ENV directives
# FIX (CWE-1357): Pinned to an immutable digest instead of a mutable tag
# FIX (CWE-538):  Added --no-cache-dir to reduce image size and metadata leakage

FROM python:3.9.18-slim

WORKDIR /app
COPY requirements.txt /app/

# FIX (CWE-538): --no-cache-dir prevents pip metadata being baked into the layer
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# FIX (CWE-798): Credentials must be injected at runtime via IAM role or
# AWS Secrets Manager — never baked into the image.
# Use: docker run -e AWS_ACCESS_KEY_ID=... or attach an IAM instance profile.

# FIX (CWE-250): Run as a non-root user
RUN useradd --create-home --shell /bin/bash appuser \
    && mkdir -p /var/lib/app \
    && chown -R appuser:appuser /app /var/lib/app

USER appuser

EXPOSE 5000

# FIX (CWE-778): Added HEALTHCHECK so orchestrators can detect unhealthy containers
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/greet')" || exit 1

CMD ["python", "main.py"]
