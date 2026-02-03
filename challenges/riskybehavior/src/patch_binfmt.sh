#!/bin/sh
set -eu

bin="${1:?usage: patch_binfmt.sh <elf-file>}"
osabi="${EI_OSABI:-0}"
abiver="${EI_ABIVERSION:-1}"

# Patch e_ident[7]=EI_OSABI and e_ident[8]=EI_ABIVERSION in-place, using only
# POSIX tools. This is intentionally dependency-free so it works on minimal
# systems.
#
# Note: we only need EI_OSABI=0 and EI_ABIVERSION=1 for this challenge.
if [ "$osabi" != "0" ] || [ "$abiver" != "1" ]; then
  echo "patch_binfmt.sh: unsupported EI_OSABI/EI_ABIVERSION ($osabi/$abiver); expected 0/1" >&2
  exit 2
fi

# Verify ELF magic
magic="$(dd if="$bin" bs=1 count=4 status=none | od -An -t u1 | tr -d ' ')"
if [ "$magic" != "127697670" ]; then
  echo "patch_binfmt.sh: $bin is not an ELF (bad magic)" >&2
  exit 1
fi

# Write raw bytes (offsets 7 and 8) and verify.
printf '\000' | dd of="$bin" bs=1 seek=7 count=1 conv=notrunc status=none
#
# Also patch the e_ident padding bytes (9..15) to a non-zero marker.
# Many qemu-binfmt registrations require these bytes to be 0x00, so changing
# them helps defeat alternative binfmt rules that might ignore EI_ABIVERSION.
#
# Layout:
# - offset 8:  EI_ABIVERSION (1)
# - offset 9-15: EI_PAD (set to ASCII marker)
printf '\001RISKY!!' | dd of="$bin" bs=1 seek=8 count=8 conv=notrunc status=none

bytes="$(dd if="$bin" bs=1 skip=7 count=2 status=none | od -An -t u1)"
printf 'patched e_ident[7..8]=%s\n' "$bytes"

# Hard fail if not exactly "0 1" (allowing arbitrary whitespace from od).
case "$bytes" in
  *" 0"*" 1"*) : ;;
  *) echo "patch_binfmt.sh: verification failed (wanted 0 1)" >&2; exit 1 ;;
esac

pad="$(dd if="$bin" bs=1 skip=9 count=7 status=none | od -An -t x1)"
printf 'patched e_ident[9..15]=%s\n' "$pad"

