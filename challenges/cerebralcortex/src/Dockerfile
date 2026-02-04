FROM ubuntu:24.04

# Toolchain for bare-metal Cortex-M builds (arm-none-eabi-gcc + binutils + newlib specs).
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    make \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    libnewlib-arm-none-eabi \
  && rm -rf /var/lib/apt/lists/*

# We mount this directory (src/) at /work when running.
WORKDIR /work

ENTRYPOINT ["make"]
CMD ["all"]

