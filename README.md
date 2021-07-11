mbedtls-example
=====

## Use **mbedtls v2.26.0 or newer** but **under v3.0.0**

-----

- ECDSA with P-256
```
gcc -o mbedecdsa mbedecdsa.c -lmbedcrypto -lmbedtls -lmbedx509
```

- ECDH with P-256 (KDF Use SHA256, NIST.SP.800-56A)
```
gcc -o mbedecdh mbedecdh.c -lmbedcrypto -lmbedtls -lmbedx509
```

-----

## troubleshooting

if you meet some error like this, you can solve by reinstall your mbedtls library run `sudo make uninstall && make clean` then `make && sudo make install`
```
❯ ./mbedecdh
 failed
  ! mbedtls_ecdh_calc_secret returned -19584
  + Z: C200000000000000479C64CEFD7F0000469C64CEFD7F00009D538CADE6550000
  + Key: E5E1E9F83F73485E851B7D0E1A7E078DBA00CDDD9F11F0264275FA090F02BC3E
 ok
```
