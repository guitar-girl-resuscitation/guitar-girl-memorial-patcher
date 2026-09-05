FROM docker.io/library/ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openjdk-21-jre-headless python3 python3-venv git unzip socat \
    libstdc++6 zlib1g && apt-get clean
# Explicit inputs: never COPY the operator's work directory or original package.
COPY ggfm-patcher ggfm-patcher-web classes.dex libggfm_bootstrap.so libdobby.so libggfm_server.so /opt/ggfm/bundle/
COPY dependencies.json docker-lock.json release-manifest.json LICENSE DOBBY-LICENSE THIRD_PARTY_TERMINAL_FONT.md /opt/ggfm/bundle/
COPY prepare.py entrypoint.py healthcheck.py /opt/ggfm/docker/
RUN python3 /opt/ggfm/docker/prepare.py \
    && python3 -m venv /opt/ggfm/venv \
    && /opt/ggfm/venv/bin/pip install --no-cache-dir --only-binary=:all: --no-binary=tpk_ar -r /opt/ggfm/patch/tools/requirements.lock.txt \
    && groupadd --gid 10001 ggfm && useradd --uid 10001 --gid ggfm --no-create-home ggfm \
    && mkdir -p /data /input && chown ggfm:ggfm /data \
    && git config --system --add safe.directory /opt/ggfm/patch
USER 10001:10001
ENV JAVA_TOOL_OPTIONS="-Xmx768m -XX:ActiveProcessorCount=2" \
    GIT_OPTIONAL_LOCKS=0 HOME=/data TMPDIR=/data/tmp RUST_LOG=info
WORKDIR /opt/ggfm
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30m --retries=3 \
    CMD ["/opt/ggfm/venv/bin/python", "/opt/ggfm/docker/healthcheck.py"]
ENTRYPOINT ["/opt/ggfm/venv/bin/python", "/opt/ggfm/docker/entrypoint.py"]
