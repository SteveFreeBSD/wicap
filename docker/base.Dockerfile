# WICAP Base Image
# Contains system dependencies, drivers, and static tools to minimize
# bandwidth usage during frequent rebuilds.

FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# =============================================================================
# SYSTEM DEPENDENCIES (APT)
# =============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg2 \
    tcpdump \
    aircrack-ng \
    hashcat \
    hcxdumptool \
    hcxtools \
    pciutils \
    procps \
    net-tools \
    iproute2 \
    wireless-tools \
    iw \
    unixodbc \
    unixodbc-dev \
    tshark \
    wireshark-common \
    cewl \
    ruby \
    git \
    make \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# MICROSOFT ODBC DRIVER
# =============================================================================
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/11/prod bullseye main" > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# STATIC TOOLS (Git Clones)
# =============================================================================

# Pipal
RUN git clone --depth 1 https://github.com/digininja/pipal.git /opt/pipal \
    && chmod +x /opt/pipal/pipal.rb \
    && echo '#!/bin/bash' > /usr/local/bin/pipal \
    && echo 'cd /opt/pipal && ruby pipal.rb "$@"' >> /usr/local/bin/pipal \
    && chmod +x /usr/local/bin/pipal

# PACK
RUN git clone --depth 1 https://github.com/iphelix/pack.git /opt/pack \
    && cd /opt/pack && 2to3 -w -n *.py \
    && sed -i 's/string\.lowercase/string.ascii_lowercase/g' /opt/pack/*.py \
    && sed -i 's/string\.uppercase/string.ascii_uppercase/g' /opt/pack/*.py \
    && sed -i 's/string\.letters/string.ascii_letters/g' /opt/pack/*.py \
    && chmod +x /opt/pack/statsgen.py /opt/pack/maskgen.py /opt/pack/policygen.py \
    && ln -s /opt/pack/statsgen.py /usr/local/bin/statsgen.py \
    && ln -s /opt/pack/maskgen.py /usr/local/bin/maskgen.py

# Princeprocessor
RUN git clone --depth 1 https://github.com/hashcat/princeprocessor.git /opt/princeprocessor \
    && cd /opt/princeprocessor/src && make \
    && ln -s /opt/princeprocessor/src/pp64.bin /usr/local/bin/pp64
