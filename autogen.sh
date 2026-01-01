#!/bin/sh
# autogen.sh - Bootstrap GNU Autotools for Mcaster1BackDraft
set -e

echo "==> Mcaster1BackDraft: bootstrapping autotools..."

for tool in aclocal autoconf autoheader automake; do
    command -v "$tool" > /dev/null 2>&1 || { echo "ERROR: $tool not found. Install autoconf automake."; exit 1; }
done

aclocal -I m4
autoconf
autoheader
automake --add-missing --copy --foreign

echo ""
echo "Done. Now run:"
echo "  ./configure"
echo "  make -j\$(nproc)"
