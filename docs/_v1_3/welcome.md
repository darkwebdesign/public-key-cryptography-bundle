---
layout: default
title: Welcome
nav_order: 1
redirect_from:
  - /
  - /docs
  - /docs/
  - /docs/1.3/
  - /docs/latest
  - /docs/latest/
  - /docs/latest/welcome
---

# Public Key Cryptography Bundle

[![Build Status](https://travis-ci.com/darkwebdesign/public-key-cryptography-bundle.svg?branch=1.3)](https://travis-ci.com/darkwebdesign/public-key-cryptography-bundle)
[![PHP Version](https://img.shields.io/badge/php-7.2%2B-777BB3.svg)](https://php.net/)
[![Symfony Version](https://img.shields.io/badge/symfony-5.x-93C74B.svg)](https://symfony.com/)
[![License](https://poser.pugx.org/darkwebdesign/public-key-cryptography-bundle/license?format=flat)](https://packagist.org/packages/darkwebdesign/public-key-cryptography-bundle)

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

## Dependencies

* `openssl` shell command

## License

Public Key Cryptography Bundle is licensed under the MIT License - see the `LICENSE` file for details.
