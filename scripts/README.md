# Scripts

Standalone helper scripts. They don't depend on the rest of the repo or on
any infrastructure.

## split-p12.sh

Splits an OCES3 certificate in PKCS#12 form (`.p12`) into PEM files, for
tools that want the certificate and private key separately.

```sh
./split-p12.sh <file.p12> [output-name]
```

| Output | Contents |
| --- | --- |
| `<name>.crt` | The certificate |
| `<name>.key` | The private key, **unencrypted** (PKCS#8), mode 600 |
| `<name>.chain.crt` | The CA certificates in the bundle, if there are any |

`output-name` defaults to the input file name without `.p12`:

```sh
./split-p12.sh ~/certs/my-system.p12             # ~/certs/my-system.crt and .key
./split-p12.sh ~/certs/my-system.p12 /tmp/my-sp  # /tmp/my-sp.crt and .key
```

- It asks for the `.p12` password once. Set `P12_PASSWORD` to skip the
  prompt, e.g. in another script.
- It checks that the private key belongs to the certificate and fails if it
  doesn't.
- It never overwrites existing files. If a step fails, it removes the files
  it already wrote.
- At the end it prints the certificate's subject and expiry date, so you can
  check you got the right certificate.

Needs OpenSSL 3. OCES3 files use modern encryption, so `-legacy` isn't
needed. If OpenSSL can't open a file even with the right password, check
whether `openssl pkcs12 -legacy -in <file.p12> -noout` can. If it can, the
file isn't a standard OCES3 export.

**The `.key` file is unencrypted.** Once the key is stored where it's needed
(a secrets manager, an encrypted file), delete it:

```sh
shred -u <name>.key
```

Keep the password-protected `.p12` as the original.
