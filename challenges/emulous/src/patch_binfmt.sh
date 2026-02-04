#!/bin/sh
set -eu

bin="${1:?usage: patch_binfmt.sh <elf-file>}"
osabi="${EI_OSABI:-0}"
abiver="${EI_ABIVERSION:-1}"

# Patch ELF e_ident bytes to defeat common qemu-binfmt registrations.
# We follow the same approach as `riskybehavior`:
# - set EI_ABIVERSION (e_ident[8]) to 1 (many rules require 0)
# - make EI_PAD (e_ident[9..15]) non-zero (some rules mask out EI_ABIVERSION)
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

# e_ident layout:
# - offset 7:  EI_OSABI
# - offset 8:  EI_ABIVERSION
# - offset 9-15: EI_PAD
printf '\000' | dd of="$bin" bs=1 seek=7 count=1 conv=notrunc status=none
printf '\001EMULOUS' | dd of="$bin" bs=1 seek=8 count=8 conv=notrunc status=none

bytes="$(dd if="$bin" bs=1 skip=7 count=2 status=none | od -An -t u1)"
printf 'patched e_ident[7..8]=%s\n' "$bytes"

case "$bytes" in
  *" 0"*" 1"*) : ;;
  *) echo "patch_binfmt.sh: verification failed (wanted 0 1)" >&2; exit 1 ;;
esac

pad="$(dd if="$bin" bs=1 skip=9 count=7 status=none | od -An -t x1)"
printf 'patched e_ident[9..15]=%s\n' "$pad"

