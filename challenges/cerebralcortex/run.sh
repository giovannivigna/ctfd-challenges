#!/bin/bash

# Run the Cortex-M image in QEMU full-system mode.
# Uses semihosting for stdout/exit. The firmware reads /flag from an embedded
# filesystem inside the firmware image (intentionally wrong by default).

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null && pwd )"

cd "$DIR"

if command -v qemu-system-arm >/dev/null 2>&1; then
  exec qemu-system-arm -M lm3s6965evb -nographic \
    -kernel src/cerebralcortex.elf \
    -semihosting-config enable=on,target=native
fi

# Portable fallback: run QEMU in a container.
exec docker run --rm \
  -v "$DIR":/work \
  -w /work \
  ubuntu:22.04 bash -lc \
  "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y qemu-system-arm ca-certificates && \
   qemu-system-arm -M lm3s6965evb -nographic -kernel src/cerebralcortex.elf -semihosting-config enable=on,target=native"

