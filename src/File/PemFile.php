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

use DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException;
use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\Process\Process;

/**
 * @author Raymond Schouten
 *
 * @since 1.0
 */
class PemFile extends CryptoFile
{
    /**
     * Validates that the file is actually a PEM file containing a public/private key pair.
     */
    protected function validate(): bool
    {
        $in = escapeshellarg($this->getPathname());

        $process = Process::fromShellCommandline("openssl x509 -in $in -noout");
        $process->run();

        if (!$process->isSuccessful()) {
            return false;
        }

        $process = Process::fromShellCommandline("openssl rsa -in $in -passin pass:anypass -check -noout");
        $process->run();

        $badDecrypt = false !== strpos($process->getErrorOutput(), ':bad decrypt:');

        if (!$process->isSuccessful() && !$badDecrypt) {
            return false;
        }

        return true;
    }

    /**
     * Sanitizes the PEM file, removing malicious data.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown.
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function sanitize(string $passPhrase = null): PemFile
    {
        if ('' === $passPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg((string) $passPhrase);

        if (null !== $passPhrase) {
            $rsaPassOut = "-passout pass:$pass -des3";
        } else {
            $rsaPassOut = '';
        }

        $process1 = Process::fromShellCommandline("openssl x509 -in $in");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl rsa -in $in -passin pass:$pass $rsaPassOut");
        $process2->mustRun();

        @file_put_contents($this->getPathname(), $process1->getOutput() . $process2->getOutput());
        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * Creates a new PEM file from a public/private key pair.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown. Pass NULL as pass phrase if you want no
     * pass phrase on the private key instead.
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public static function create(string $path, PublicKeyFile $publicKeyFile, PrivateKeyFile $privateKeyFile, string $privateKeyPassPhrase = null): PemFile
    {
        if ('' === $privateKeyPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $publicKeyIn = escapeshellarg($publicKeyFile->getPathname());
        $publicKeyInForm = escapeshellarg($publicKeyFile->getFormat());
        $privateKeyIn = escapeshellarg($privateKeyFile->getPathname());
        $privateKeyInForm = escapeshellarg($privateKeyFile->getFormat());
        $privateKeyPass = escapeshellarg((string) $privateKeyPassPhrase);

        if (null !== $privateKeyPassPhrase) {
            $rsaPassOut = "-passout pass:$privateKeyPass -des3";
        } else {
            $rsaPassOut = '';
        }

        $process1 = Process::fromShellCommandline("openssl rsa -in $privateKeyIn -inform $privateKeyInForm -passin pass:$privateKeyPass $rsaPassOut");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl x509 -in $publicKeyIn -inform $publicKeyInForm");
        $process2->mustRun();

        @file_put_contents($path, $process1->getOutput() . $process2->getOutput());
        @chmod($path, 0666 & ~umask());

        return new self($path);
    }

    /**
     * Gets a keystore containing the public/private key pair.
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getKeystore(string $path, string $keystorePassPhrase, string $privateKeyPassPhrase = null): KeystoreFile
    {
        $in = escapeshellarg($this->getPathname());
        $keystorePass = escapeshellarg($keystorePassPhrase);
        $privateKeyPass = escapeshellarg((string) $privateKeyPassPhrase);

        $process = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$privateKeyPass -passout pass:$keystorePass -export");
        $process->mustRun();

        @file_put_contents($path, $process->getOutput());
        @chmod($path, 0666 & ~umask());

        return new KeystoreFile($path);
    }

    /**
     * Gets the public key.
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPublicKey(string $path): PublicKeyFile
    {
        $in = escapeshellarg($this->getPathname());

        $process = Process::fromShellCommandline("openssl x509 -in $in");
        $process->mustRun();

        @file_put_contents($path, $process->getOutput());
        @chmod($path, 0666 & ~umask());

        return new PublicKeyFile($path);
    }

    /**
     * Gets the private key.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown. Pass NULL as pass phrase if you want no
     * pass phrase on the private key instead.
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPrivateKey(string $path, string $passPhrase = null): PrivateKeyFile
    {
        if ('' === $passPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg((string) $passPhrase);

        if (null !== $passPhrase) {
            $rsaPassOut = "-passout pass:$pass -des3";
        } else {
            $rsaPassOut = '';
        }

        $process = Process::fromShellCommandline("openssl rsa -in $in -passin pass:$pass $rsaPassOut");
        $process->mustRun();

        @file_put_contents($path, $process->getOutput());
        @chmod($path, 0666 & ~umask());

        return new PrivateKeyFile($path);
    }

    /**
     * Gets the public key "subject" attribute.
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getSubject(): string
    {
        $in = escapeshellarg($this->getPathname());

        $process = Process::fromShellCommandline("openssl x509 -in $in -noout -subject");
        $process->mustRun();

        return trim(preg_replace('/^subject=/', '', $process->getOutput()));
    }

    /**
     * Gets the public key "issuer" attribute.
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getIssuer(): string
    {
        $in = escapeshellarg($this->getPathname());

        $process = Process::fromShellCommandline("openssl x509 -in $in -noout -issuer");
        $process->mustRun();

        return trim(preg_replace('/^issuer=/', '', $process->getOutput()));
    }

    /**
     * Gets the public key "notBefore" attribute.
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getNotBefore(): \DateTime
    {
        $in = escapeshellarg($this->getPathname());

        $process = Process::fromShellCommandline("openssl x509 -in $in -noout -startdate");
        $process->mustRun();

        return new \DateTime(trim(preg_replace('/^notBefore=/', '', $process->getOutput())));
    }

    /**
     * Gets the public key "notAfter" attribute.
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getNotAfter(): \DateTime
    {
        $in = escapeshellarg($this->getPathname());

        $process = Process::fromShellCommandline("openssl x509 -in $in -noout -enddate");
        $process->mustRun();

        return new \DateTime(trim(preg_replace('/^notAfter=/', '', $process->getOutput())));
    }

    /**
     * Checks if the private key contains a pass phrase.
     */
    public function hasPassPhrase(): bool
    {
        $in = escapeshellarg($this->getPathname());

        $process1 = Process::fromShellCommandline("openssl rsa -in $in -passin pass:nopass -check -noout");
        $process1->run();

        $process2 = Process::fromShellCommandline("openssl rsa -in $in -passin pass:anypass -check -noout");
        $process2->run();

        return !$process1->isSuccessful() && !$process2->isSuccessful();
    }

    /**
     * Verifies a pass phrase against the private key.
     *
     * This methods verifies if the specified pass phrase can be used to read the private key. This means that verifying
     * a private key without a pass phrase will always return true for all specified pass phrases.
     */
    public function verifyPassPhrase(string $passPhrase): bool
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $process = Process::fromShellCommandline("openssl rsa -in $in -passin pass:$pass -check -noout");
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * Adds a pass phrase to the private key.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown.
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function addPassPhrase(string $passPhrase): PemFile
    {
        if ('' === $passPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $process1 = Process::fromShellCommandline("openssl x509 -in $in");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl rsa -in $in -passin pass:nopass -passout pass:$pass -des3");
        $process2->mustRun();

        @file_put_contents($this->getPathname(), $process1->getOutput() . $process2->getOutput());
        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * Removes the pass phrase from the private key.
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function removePassPhrase(string $passPhrase): PemFile
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $process1 = Process::fromShellCommandline("openssl x509 -in $in");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl rsa -in $in -passin pass:$pass");
        $process2->mustRun();

        @file_put_contents($this->getPathname(), $process1->getOutput() . $process2->getOutput());
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
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function changePassPhrase(string $passPhrase, string $newPassPhrase): PemFile
    {
        if ('' === $newPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);
        $newPass = escapeshellarg($newPassPhrase);

        $process1 = Process::fromShellCommandline("openssl x509 -in $in");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl rsa -in $in -passin pass:$pass -passout pass:$newPass -des3");
        $process2->mustRun();

        @file_put_contents($this->getPathname(), $process1->getOutput() . $process2->getOutput());
        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * Moves the file to a new location.
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     *
     * @throws \Symfony\Component\HttpFoundation\File\Exception\FileException
     */
    public function move(string $directory, string $name = null): File
    {
        $file = parent::move($directory, $name);

        return new self($file->getPathname());
    }
}
