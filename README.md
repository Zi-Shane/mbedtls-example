mbedtls-example
=====

## Use ***mbedtls v2.26.0**

-----

- ECDSA with P-256

- ECDH with P-256 (KDF Use SHA256, NIST.SP.800-56A)

-----

```
gcc -o mbedecdsa mbedecdsa.c -lmbedcrypto -lmbedtls -lmbedx509
```
