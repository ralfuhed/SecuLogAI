FROM python:3.11-slim

# Analysis containers handle untrusted log data, so the process does not run
# as root. A parser bug should not become a container escape.
RUN useradd --create-home --shell /usr/sbin/nologin seculog

WORKDIR /app

# Dependencies first so the layer caches across source edits.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir gunicorn==23.0.0

COPY --chown=seculog:seculog . .

# Runtime output directories, owned by the unprivileged user.
RUN mkdir -p data/results data/uploads && chown -R seculog:seculog data

USER seculog

EXPOSE 5000

# Binding 0.0.0.0 is required inside a container, the container boundary is
# what limits reach, not the bind address. docker-compose publishes the port
# to 127.0.0.1 only, so this is not exposed to the LAN by default.
#
# gunicorn rather than the Flask development server: the dev server is
# single-threaded and explicitly not intended to face anything.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", \
     "--timeout", "300", "web.app:app"]
