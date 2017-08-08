# Public Key Cryptography Bundle

[![Latest Stable Version](https://poser.pugx.org/darkwebdesign/public-key-cryptography-bundle/v/stable?format=flat)](https://packagist.org/packages/darkwebdesign/public-key-cryptography-bundle)
[![Total Downloads](https://poser.pugx.org/darkwebdesign/public-key-cryptography-bundle/downloads?format=flat)](https://packagist.org/packages/darkwebdesign/public-key-cryptography-bundle)
[![License](https://poser.pugx.org/darkwebdesign/public-key-cryptography-bundle/license?format=flat)](https://packagist.org/packages/darkwebdesign/public-key-cryptography-bundle)

[![Build Status](https://travis-ci.org/darkwebdesign/public-key-cryptography-bundle.svg?branch=master)](https://travis-ci.org/darkwebdesign/public-key-cryptography-bundle?branch=master)
[![Coverage Status](https://codecov.io/gh/darkwebdesign/public-key-cryptography-bundle/branch/master/graph/badge.svg)](https://codecov.io/gh/darkwebdesign/public-key-cryptography-bundle)
[![Minimum PHP Version](https://img.shields.io/badge/php-%3E%3D%205.3-blue.svg)](https://php.net/)
[![Minimum Symfony Version](https://img.shields.io/badge/symfony-%3E%3D%202.3-green.svg)](https://symfony.com/)

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

### Passphrase management

* Adds/removes passphrase from PEM/private key.
* Changes passphrase of keystore/PEM/private key.

## Dependencies

* `openssl` and `keytool` shell commands

## Installing via Composer

```bash
composer require darkwebdesign/public-key-cryptography-bundle
```

```bash
composer install
```

## License

Public Key Cryptography Bundle is licensed under the MIT License - see the `LICENSE` file for details.
