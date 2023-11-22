---
layout: default
title: Known Issues
redirect_from:
  - /docs/latest/known-issues
---

# Known Issues

* `openssl rsa` (at least 0.9.8zh) isn't able to read PKCS#8 private keys in DER format.
* `openssl rsa` (at least 1.0.1e-fips) isn't able to read PKCS#8 private keys in DER format containing a pass phrase.
* `openssl rsa` (at least 0.9.8zh and 1.0.1e-fips) isn't able to output RSA private keys in DER format with a pass phrase;
  private key will be outputted, but without a pass phrase.

According to the OpenSSL Software Foundation, the 0.9.8, 1.0.0 and 1.0.1 versions are out of support and should not be used.
