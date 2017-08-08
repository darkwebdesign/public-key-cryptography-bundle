#!/bin/bash

php -d zend_extension='/usr/local/php/lib/php/extensions/no-debug-non-zts-20090626/xdebug.so' vendor/bin/phpunit
