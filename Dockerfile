FROM eclipse-temurin:21-jdk-noble

ARG GHIDRA_VERSION=12.1.4
ARG GHIDRA_DATE=20250619

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv unzip wget && \
    wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_* /opt/ghidra && \
    rm /tmp/ghidra.zip && \
    apt-get purge -y unzip wget && \
    apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

COPY . /src
RUN pip3 install --break-system-packages --no-cache-dir /src && \
    rm -rf /src

ENTRYPOINT ["ghidra-decomp"]
