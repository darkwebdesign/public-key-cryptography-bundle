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
use DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile;
use Symfony\Component\Process\Process;

/**
 * @author Raymond Schouten
 *
 * @since 1.0
 *
 * @todo verify needs to exclude PEM files
 */
class PublicKeyFile extends CryptoFile
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
            openssl x509 -in $in -inform $inForm -noout && 
            ! (
                error=$(openssl rsa -in $in -inform $inForm -passin pass: -check -noout 2>&1 >/dev/null) ||
                echo \"\$error\" | grep --regexp ':bad password read:' ||
                error=$(openssl pkcs8 -in $in -inform $inForm -passin pass: 2>&1 >/dev/null) ||
                echo \"\$error\" | grep --regexp ':bad decrypt:'
            )";

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
     * @return string
     */
    public function getSubject()
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());

        $command = "openssl x509 -in $in -inform $inForm -noout -subject";

        $process = new Process($command);
        $process->mustRun();

        return trim(preg_replace('/^subject=/', '', $process->getOutput()));
    }

    /**
     * @return string
     */
    public function getIssuer()
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());

        $command = "openssl x509 -in $in -inform $inForm -noout -issuer";

        $process = new Process($command);
        $process->mustRun();

        return trim(preg_replace('/^issuer=/', '', $process->getOutput()));
    }

    /**
     * @return \DateTime
     */
    public function getNotBefore()
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());

        $command = "openssl x509 -in $in -inform $inForm -noout -startdate";

        $process = new Process($command);
        $process->mustRun();

        return new \DateTime(trim(preg_replace('/^notBefore=/', '', $process->getOutput())));
    }

    /**
     * @return \DateTime
     */
    public function getNotAfter()
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());

        $command = "openssl x509 -in $in -inform $inForm -noout -enddate";

        $process = new Process($command);
        $process->mustRun();

        return new \DateTime(trim(preg_replace('/^notAfter=/', '', $process->getOutput())));
    }

    /**
     * @param string $format
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile
     *
     * @throws \InvalidArgumentException
     */
    public function convertFormat($format)
    {
        if (!defined('DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile::FORMAT_' . strtoupper($format))) {
            throw new \InvalidArgumentException(sprintf('Invalid format "%s".', $format));
        }

        if ($this->getFormat() === strtolower($format)) {
            return $this;
        }

        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());
        $outForm = escapeshellarg($format);

        $command = "
            openssl x509 -in $in -inform $inForm -out $in~ -outform $outForm &&
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
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile
     *
     * @throws \Symfony\Component\HttpFoundation\File\Exception\FileException
     */
    public function move($directory, $name = null)
    {
        $file = parent::move($directory, $name);

        return new self($file->getPathname());
    }
}
