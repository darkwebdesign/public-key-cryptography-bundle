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

use DarkWebDesign\PublicKeyCryptographyBundle\Exception\FormatNotValidException;
use DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException;
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

        $command = "openssl rsa -in $in -inform $inForm -passin pass: -check -noout";

        $process = new Process($command);
        $process->run();

        $badPasswordRead = false !== strpos($process->getErrorOutput(), ':bad password read:');

        if (!$process->isSuccessful() && !$badPasswordRead) {
            return false;
        }

        $command = "openssl x509 -in $in -inform $inForm -noout";

        $process = new Process($command);
        $process->run();

        if ($process->isSuccessful()) {
            return false;
        }

        return true;
    }

    /**
     * @return string
     */
    public function getFormat()
    {
        return $this->isBinary() ? static::FORMAT_DER : static::FORMAT_PEM;
    }

    /**
     * @param string $format
     * @param string|null $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FormatNotValidException
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function convertFormat($format, $passPhrase = null)
    {
        $format = strtolower($format);

        if (!defined('DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile::FORMAT_' . strtoupper($format))) {
            throw new FormatNotValidException($format);
        }

        if ($this->getFormat() === $format) {
            return $this;
        }

        if ('' === $passPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());
        $outForm = escapeshellarg($format);
        $pass = escapeshellarg($passPhrase);

        if (null !== $passPhrase) {
            $rsaPassOut = "-passout pass:$pass -des3";
        } else {
            $rsaPassOut = '';
        }

        $command = "
            openssl rsa -in $in -inform $inForm -passin pass:$pass -out $in~ -outform $outForm $rsaPassOut &&
            mv $in~ $in ||
            rm $in~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * @return bool
     */
    public function hasPassPhrase()
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());

        $command = "openssl rsa -in $in -inform $inForm -passin pass: -check -noout";

        $process = new Process($command);
        $process->run();

        return !$process->isSuccessful();
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
