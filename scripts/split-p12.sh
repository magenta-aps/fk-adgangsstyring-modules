#!/usr/bin/env bash
#
# Splits a PKCS#12 (.p12/.pfx) file into PEM files:
#
#   <name>.crt        the certificate
#   <name>.key        the private key, UNENCRYPTED (PKCS#8), mode 600
#   <name>.chain.crt  any CA certificates in the bundle (only if there are any)
#
# and checks that the key belongs to the certificate.
#
# Usage: split-p12.sh <file.p12> [output-name]
#
# output-name defaults to the input file name without its extension, so
# certs/foo.p12 gives certs/foo.crt and certs/foo.key. The password is asked
# for once; set P12_PASSWORD to skip the prompt. Existing files are never
# overwritten.
set -euo pipefail

usage() {
    echo "Usage: $(basename "$0") <file.p12> [output-name]" >&2
    exit 2
}

[ $# -ge 1 ] && [ $# -le 2 ] || usage
in="$1"
[ -f "$in" ] || { echo "No such file: $in" >&2; exit 1; }

name="${2:-${in%.*}}"
crt="$name.crt"
key="$name.key"
chain="$name.chain.crt"

outdir="$(dirname "$name")"
[ -d "$outdir" ] || { echo "No such directory: $outdir" >&2; exit 1; }

for f in "$crt" "$key" "$chain"; do
    if [ -e "$f" ]; then
        echo "$f already exists; remove it or pick another output name." >&2
        exit 1
    fi
done

if [ -z "${P12_PASSWORD+x}" ]; then
    read -rsp "Password for $in: " P12_PASSWORD
    echo >&2
fi
export P12_PASSWORD

p12() {
    openssl pkcs12 -in "$in" -passin env:P12_PASSWORD "$@"
}

if ! p12 -noout 2>/dev/null; then
    echo "Can't read $in: wrong password or not a PKCS#12 file." >&2
    exit 1
fi

# The key must never be readable by others, not even for a moment.
umask 077

# Remove partial output if anything below fails.
trap 'rm -f "$crt" "$key" "$chain"' ERR

# The pipes through x509/pkey drop the "Bag Attributes" headers.
p12 -clcerts -nokeys | openssl x509 -out "$crt"
p12 -nocerts -nodes | openssl pkey -out "$key"

cas="$(p12 -cacerts -nokeys | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p')"
if [ -n "$cas" ]; then
    printf '%s\n' "$cas" > "$chain"
fi

chmod 644 "$crt"
[ ! -e "$chain" ] || chmod 644 "$chain"

cert_pub="$(openssl x509 -in "$crt" -noout -pubkey | sha256sum)"
key_pub="$(openssl pkey -in "$key" -pubout | sha256sum)"
if [ "$cert_pub" != "$key_pub" ]; then
    echo "The private key does not match the certificate." >&2
    false
fi

trap - ERR

echo "Certificate: $crt"
echo "Private key: $key (unencrypted, delete it when you're done)"
[ ! -e "$chain" ] || echo "CA chain:    $chain"
openssl x509 -in "$crt" -noout -subject -enddate
