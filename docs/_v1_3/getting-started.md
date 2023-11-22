---
layout: default
title: Getting Started
nav_order: 2
redirect_from:
  - /docs/latest/getting-started
---

# Getting Started

## Installing & Setting up

### Installing via Composer

If you don't have Composer installed in your computer, start by [installing Composer globally](https://getcomposer.org/). Then,
execute the following commands to install the required dependencies:

```bash
composer require darkwebdesign/public-key-cryptography-bundle
```

```bash
composer install
```

### Enabling the bundle in Symfony

```php
// config/bundles.php
return [
    // ...
    DarkWebDesign\PublicKeyCryptographyBundle\PublicKeyCryptographyBundle::class => ['all' => true],
];
```
