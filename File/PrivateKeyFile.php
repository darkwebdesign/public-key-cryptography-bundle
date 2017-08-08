<?php
/**
 * Copyright (c) 2017 DarkWeb Design
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace DarkWebDesign\PublicKeyCryptographyBundle\File;

use DarkWebDesign\PublicKeyCryptographyBundle\File\CryptoFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile;
use Symfony\Component\Process\Process;

/**
 * @author Raymond Schouten
 *
 * @since 1.0
 */
class PrivateKeyFile extends CryptoFile
{
    const FORMAT_PEM = 'pem';
    const FORMAT_DER = 'der';

    /**
     * @return bool
     */
    protected function validate()
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());

        // issue: `openssl rsa` can't read PKCS#8 DER format with passphrase -> use `openssl pkcs8` as fallback
        $command = "
            (
                error=$(openssl rsa -in $in -inform $inForm -passin pass: -check -noout 2>&1 >/dev/null) ||
                echo \"\$error\" | grep --regexp ':bad password read:' ||
                error=$(openssl pkcs8 -in $in -inform $inForm -passin pass: 2>&1 >/dev/null) ||
                echo \"\$error\" | grep --regexp ':bad decrypt:'
            ) &&
            ! openssl x509 -in $in -inform $inForm -noout";

        $process = new Process($command);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * @return string
     */
    public function getFormat()
    {
        return $this->isBinary() ? static::FORMAT_DER : static::FORMAT_PEM;
    }

    /**
     * @param string      $format
     * @param string|null $password
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \InvalidArgumentException
     */
    public function convertFormat($format, $password = null)
    {
        if (!defined('DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile::FORMAT_' . strtoupper($format))) {
            throw new \InvalidArgumentException(sprintf('Invalid format "%s".', $format));
        }

        if ($this->getFormat() === strtolower($format)) {
            return $this;
        }

        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());
        $outForm = escapeshellarg($format);
        $pass = escapeshellarg($password);

        if (null !== $password) {
            $rsaPassOut = "-passout pass:$password -des3";
            $pkcs8PassIn = "-passin pass:$password";
        } else {
            $rsaPassOut = '';
            $pkcs8PassIn = '-nocrypt';
        }

        // issue: `openssl rsa` can't read PKCS#8 DER format with passphrase -> use `openssl pkcs8` as fallback
        // issue: `openssl pkcs8` can't output RSA key with passphrase -> pipe to `openssl rsa`
        $command = "
            (
                openssl rsa -in $in -inform $inForm -out $in~ -outform $outForm -passin pass:$pass $rsaPassOut ||
                openssl pkcs8 -in $in -inform $inForm -outform $outForm $pkcs8PassIn |
                openssl rsa -out $in~ $rsaPassOut
            ) &&
            mv $in~ $in";

        $process = new Process($command);
        $process->mustRun();

        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * @param string $directory
     * @param string|null $name
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \Symfony\Component\HttpFoundation\File\Exception\FileException
     */
    public function move($directory, $name = null)
    {
        $file = parent::move($directory, $name);

        return new self($file->getPathname());
    }
}
