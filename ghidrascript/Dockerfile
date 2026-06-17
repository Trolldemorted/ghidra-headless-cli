# Ghidra 12.x requires JDK 21.
FROM eclipse-temurin:21-jdk-jammy

# Pinned to the build this code was developed against; override to mirror or upgrade.
# GHIDRA_SHA256 is optional (verified only when set).
ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_DATE=20260605
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip
ARG GHIDRA_SHA256=

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fSL "$GHIDRA_URL" -o /tmp/ghidra.zip \
 && if [ -n "$GHIDRA_SHA256" ]; then echo "$GHIDRA_SHA256  /tmp/ghidra.zip" | sha256sum -c -; fi \
 && unzip -q /tmp/ghidra.zip -d /opt \
 && rm /tmp/ghidra.zip

COPY . /opt/ghidrascript

ENV GHIDRA_INSTALL=/opt/ghidra_${GHIDRA_VERSION}_PUBLIC \
    GHIDRA_SCRIPTPATH=/opt/ghidrascript \
    GHIDRA_SCRIPT=RpcServer.java \
    RPC_BIND=0.0.0.0 \
    RPC_PORT=18000

EXPOSE 18000

# Server target + credentials are supplied at run time, e.g.:
#   docker run -e GHIDRA_ADDRESS=host:13100 -e GHIDRA_PROJECT=P3 \
#              -e GHIDRA_USER=claude -e GHIDRA_PASSWORD=... -p 18000:18000 <image>
ENTRYPOINT ["bash", "/opt/ghidrascript/ghidra-headless.sh"]
