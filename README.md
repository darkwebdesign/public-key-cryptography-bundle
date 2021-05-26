# Public Key Cryptography Bundle

[![Latest Stable Version](https://poser.pugx.org/darkwebdesign/public-key-cryptography-bundle/v/stable?format=flat)](https://packagist.org/packages/darkwebdesign/public-key-cryptography-bundle)
[![Total Downloads](https://poser.pugx.org/darkwebdesign/public-key-cryptography-bundle/downloads?format=flat)](https://packagist.org/packages/darkwebdesign/public-key-cryptography-bundle)
[![License](https://poser.pugx.org/darkwebdesign/public-key-cryptography-bundle/license?format=flat)](https://packagist.org/packages/darkwebdesign/public-key-cryptography-bundle)

[![Build Status](https://travis-ci.com/darkwebdesign/public-key-cryptography-bundle.svg?branch=1.3)](https://travis-ci.com/darkwebdesign/public-key-cryptography-bundle)
[![Coverage Status](https://codecov.io/gh/darkwebdesign/public-key-cryptography-bundle/branch/1.3/graph/badge.svg)](https://codecov.io/gh/darkwebdesign/public-key-cryptography-bundle)
[![PHP Version](https://img.shields.io/badge/php-7.2%2B-777BB3.svg)](https://php.net/)
[![Symfony Version](https://img.shields.io/badge/symfony-5.x-93C74B.svg)](https://symfony.com/)

Public Key Cryptography Bundle is a collection of public/private key cryptography components that you can use in your
Symfony applications.

## Features

### Creation

* Creates keystore from public/private keys.
* Creates PEM from public/private keys.

### Extraction

* Extracts public/private keys from keystore/PEM.
* Extracts PEM from keystore and vice versa.

### Analysis

* Checks format (PEM/DER) of public/private keys
* Checks subject, issuer, notBefore and notAfter properties from keystore/PEM/public key.
* Checks whether keystore/PEM/private key contains a passphrase.

### Conversion

* Converts public/private key format (PEM/DER).

### Pass phrase management

* Adds/removes passphrase from PEM/private key.
* Changes passphrase of keystore/PEM/private key.

## Known issues

* `openssl rsa` (at least 0.9.8zh) isn't able to read PKCS#8 private keys in DER format.
* `openssl rsa` (at least 1.0.1e-fips) isn't able to read PKCS#8 private keys in DER format containing a pass phrase.
* `openssl rsa` (at least 0.9.8zh and 1.0.1e-fips) isn't able to output RSA private keys in DER format with a pass phrase;
  private key will be outputted, but without a pass phrase.

According to the OpenSSL Software Foundation, the 0.9.8, 1.0.0 and 1.0.1 versions are out of support and should not be used.

## Installing via Composer

```bash
composer require darkwebdesign/public-key-cryptography-bundle
```

```bash
composer install
```

## Dependencies

* `openssl` shell command

## License

Public Key Cryptography Bundle is licensed under the MIT License - see the `LICENSE` file for details.
