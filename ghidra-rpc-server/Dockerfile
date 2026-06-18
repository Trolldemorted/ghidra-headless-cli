ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_DATE=20260605
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip
# Optional
ARG GHIDRA_SHA256=


FROM rust AS cli-build
WORKDIR /build
COPY --from=cli . .
RUN cargo build --release


# Ghidra 12.x requires JDK 21.
FROM eclipse-temurin:21-jdk-jammy AS ghidra
ARG GHIDRA_VERSION
ARG GHIDRA_DATE
ARG GHIDRA_URL
ARG GHIDRA_SHA256
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fSL "$GHIDRA_URL" -o /tmp/ghidra.zip \
 && if [ -n "$GHIDRA_SHA256" ]; then echo "$GHIDRA_SHA256  /tmp/ghidra.zip" | sha256sum -c -; fi \
 && unzip -q /tmp/ghidra.zip -d /opt \
 && rm /tmp/ghidra.zip \
 && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra


FROM ghidra AS ghidra-server
ARG GHIDRA_VERSION
ENTRYPOINT ["/opt/ghidra/server/ghidraSvr","console"]


FROM ghidra AS ghidra-rpc
ARG GHIDRA_VERSION
COPY . /opt/ghidra-rpc-server
ENV GHIDRA_INSTALL=/opt/ghidra_${GHIDRA_VERSION}_PUBLIC \
    GHIDRA_SCRIPTPATH=/opt/ghidra-rpc-server \
    GHIDRA_SCRIPT=RpcServer.java \
    RPC_BIND=0.0.0.0 \
    RPC_PORT=18000
EXPOSE 18000
# Server target + credentials are supplied at run time, e.g.:
#   docker run -e GHIDRA_ADDRESS=host:13100 -e GHIDRA_PROJECT=P3 \
#              -e GHIDRA_USER=claude -e GHIDRA_PASSWORD=... -p 18000:18000 <image>
#
# tini as PID 1 reaps zombies and, crucially, `-g` forwards SIGTERM to the whole process
# GROUP: Ghidra's launcher chain (analyzeHeadless -> launch.sh -> java) never execs, so the
# JVM is a grandchild that a bare bash/tini would not signal — `docker stop` would then
# SIGKILL after the grace period instead of stopping the JVM cleanly.
COPY --from=cli-build /build/target/release/ghidra-headless-cli /ghidra-headless-cli
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "bash", "/opt/ghidra-rpc-server/ghidra-headless.sh"]
