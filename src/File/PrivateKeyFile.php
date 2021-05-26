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

declare(strict_types=1);

namespace DarkWebDesign\PublicKeyCryptographyBundle\File;

use DarkWebDesign\PublicKeyCryptographyBundle\Exception\FormatNotValidException;
use DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException;
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
     * Validates that the file is actually a private key.
     *
     * Known issues:
     * OpenSSL (at lease 1.0.1e-fips) has issues reading PKCS#8 private keys in the DER format. Therefore these private
     * keys might not be successfully validated as valid private key.
     *
     * @return bool
     */
    protected function validate(): bool
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());

        $process = Process::fromShellCommandline("openssl rsa -in $in -inform $inForm -passin pass:anypass -check -noout");
        $process->run();

        $badDecrypt = false !== strpos($process->getErrorOutput(), ':bad decrypt:');

        if (!$process->isSuccessful() && !$badDecrypt) {
            return false;
        }

        $process = Process::fromShellCommandline("openssl x509 -in $in -inform $inForm -noout");
        $process->run();

        if ($process->isSuccessful()) {
            return false;
        }

        return true;
    }

    /**
     * Sanitizes the private key, removing malicious data.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown.
     *
     * @param string|null $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function sanitize(string $passPhrase = null): PrivateKeyFile
    {
        if ('' === $passPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());
        $pass = escapeshellarg((string) $passPhrase);

        if (null !== $passPhrase) {
            $rsaPassOut = "-passout pass:$pass -des3";
        } else {
            $rsaPassOut = '';
        }

        $process = Process::fromShellCommandline("openssl rsa -in $in -inform $inForm -passin pass:$pass -outform $inForm $rsaPassOut");
        $process->mustRun();

        @file_put_contents($this->getPathname(), $process->getOutput());
        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * Gets the private key format (either ascii 'pem' or binary 'der').
     *
     * @return string
     */
    public function getFormat(): string
    {
        return $this->isBinary() ? static::FORMAT_DER : static::FORMAT_PEM;
    }

    /**
     * Converts the private key format to either ascii 'pem' or binary 'der'.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown.
     *
     * Known issues:
     * OpenSSL (at lease 0.9.8zh and 1.0.1e-fips) has issues writing RSA private keys in the DER format with a pass
     * phrase. Therefore converting a pivate key with a pass phrase to the DER format might result in a private key
     * without a pass phrase.
     *
     * @param string $format
     * @param string|null $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FormatNotValidException
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function convertFormat(string $format, string $passPhrase = null): PrivateKeyFile
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
        $pass = escapeshellarg((string) $passPhrase);

        if (null !== $passPhrase) {
            $rsaPassOut = "-passout pass:$pass -des3";
        } else {
            $rsaPassOut = '';
        }

        $process = Process::fromShellCommandline("openssl rsa -in $in -inform $inForm -passin pass:$pass -outform $outForm $rsaPassOut");
        $process->mustRun();

        @file_put_contents($this->getPathname(), $process->getOutput());
        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * Checks if the private key contains a pass phrase.
     *
     * @return bool
     */
    public function hasPassPhrase(): bool
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());

        $process1 = Process::fromShellCommandline("openssl rsa -in $in -inform $inForm -passin pass:nopass -check -noout");
        $process1->run();

        $process2 = Process::fromShellCommandline("openssl rsa -in $in -inform $inForm -passin pass:anypass -check -noout");
        $process2->run();

        return !$process1->isSuccessful() && !$process2->isSuccessful();
    }

    /**
     * Verifies a pass phrase against the private key.
     *
     * This methods verifies if the specified pass phrase can be used to read the private key. This means that verifying
     * a private key without a pass phrase will always return true for all specified pass phrases.
     *
     * @param string $passPhrase
     *
     * @return bool
     */
    public function verifyPassPhrase(string $passPhrase): bool
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());
        $pass = escapeshellarg($passPhrase);

        $process = Process::fromShellCommandline("openssl rsa -in $in -inform $inForm -passin pass:$pass -check -noout");
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * Adds a pass phrase to the private key.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown.
     *
     * Known issues:
     * OpenSSL (at lease 0.9.8zh and 1.0.1e-fips) has issues writing RSA private keys in the DER format with a pass
     * phrase. Therefore adding a pass phrase to a pivate key with in the DER format might result in a private key
     * without a pass phrase.
     *
     * @param string $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function addPassPhrase(string $passPhrase): PrivateKeyFile
    {
        if ('' === $passPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());
        $pass = escapeshellarg($passPhrase);

        $process = Process::fromShellCommandline("openssl rsa -in $in -inform $inForm -passin pass:nopass -outform $inForm -passout pass:$pass -des3");
        $process->mustRun();

        @file_put_contents($this->getPathname(), $process->getOutput());
        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * Removes the pass phrase from the private key.
     *
     * @param string $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function removePassPhrase(string $passPhrase): PrivateKeyFile
    {
        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());
        $pass = escapeshellarg($passPhrase);

        $process = Process::fromShellCommandline("openssl rsa -in $in -inform $inForm -passin pass:$pass -outform $inForm");
        $process->mustRun();

        @file_put_contents($this->getPathname(), $process->getOutput());
        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * Changes the pass phrase of the private key.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown.
     *
     * @param string $passPhrase
     * @param string $newPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function changePassPhrase(string $passPhrase, string $newPassPhrase): PrivateKeyFile
    {
        if ('' === $newPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $inForm = escapeshellarg($this->getFormat());
        $pass = escapeshellarg($passPhrase);
        $newPass = escapeshellarg($newPassPhrase);

        $process = Process::fromShellCommandline("openssl rsa -in $in -inform $inForm -passin pass:$pass -outform $inForm -passout pass:$newPass -des3");
        $process->mustRun();

        @file_put_contents($this->getPathname(), $process->getOutput());
        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * Moves the file to a new location.
     *
     * @param string $directory
     * @param string|null $name
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \Symfony\Component\HttpFoundation\File\Exception\FileException
     */
    public function move($directory, $name = null): PrivateKeyFile
    {
        $file = parent::move($directory, $name);

        return new self($file->getPathname());
    }
}
