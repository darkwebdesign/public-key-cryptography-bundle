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

use Symfony\Component\Process\Process;

/**
 * @author Raymond Schouten
 *
 * @since 1.0
 */
class KeystoreFile extends CryptoFile
{
    /**
     * Validates that the file is actually a keystore containing a public/private key pair.
     *
     * @return bool
     */
    protected function validate(): bool
    {
        $in = escapeshellarg($this->getPathname());

        $process = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:anypass -noout");
        $process->run();

        $invalidPassword = false !== strpos($process->getErrorOutput(), 'invalid password');

        if (!$process->isSuccessful() && !$invalidPassword) {
            return false;
        }

        return true;
    }

    /**
     * Creates a new keystore from a public/private key pair.
     *
     * When a new keystore is created, the pass phrase of the private key contained in the keystore will be replaced by
     * the keystore pass phrase. This is because most software always assumes that the keystore pass phrase and private
     * key pass phrase are the same.
     *
     * @param string $path
     * @param string $passPhrase
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile $publicKeyFile
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile $privateKeyFile
     * @param string|null $privateKeyPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public static function create(string $path, string $passPhrase, PublicKeyFile $publicKeyFile, PrivateKeyFile $privateKeyFile, string $privateKeyPassPhrase = null): KeystoreFile
    {
        $pass = escapeshellarg($passPhrase);
        $publicKeyIn = escapeshellarg($publicKeyFile->getPathname());
        $publicKeyInForm = escapeshellarg($publicKeyFile->getFormat());
        $privateKeyIn = escapeshellarg($privateKeyFile->getPathname());
        $privateKeyInForm = escapeshellarg($privateKeyFile->getFormat());
        $privateKeyPass = escapeshellarg((string) $privateKeyPassPhrase);

        $process1 = Process::fromShellCommandline("openssl rsa -in $privateKeyIn -inform $privateKeyInForm -passin pass:$privateKeyPass -passout pass:pipe -des3");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl x509 -in $publicKeyIn -inform $publicKeyInForm");
        $process2->mustRun();

        $process3 = Process::fromShellCommandline("openssl pkcs12 -passin pass:pipe -passout pass:$pass -export");
        $process3->setInput($process1->getOutput() . $process2->getOutput());
        $process3->mustRun();

        @file_put_contents($path, $process3->getOutput());
        @chmod($path, 0666 & ~umask());

        return new self($path);
    }

    /**
     * Gets a PEM file containing the public/private key pair.
     *
     * @param string $path
     * @param string $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPem(string $path, string $passPhrase): PemFile
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        // if the keystore pass phrase is an empty string, the outputted private key will not contain a pass phrase
        if (null !== $passPhrase && '' !== $passPhrase) {
            $rsaPassOut = "-passout pass:$pass -des3";
        } else {
            $rsaPassOut = '';
        }

        $process1 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nocerts -passout pass:pipe");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl rsa -passin pass:pipe $rsaPassOut");
        $process2->setInput($process1->getOutput());
        $process2->mustRun();

        $process3 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nokeys -clcerts");
        $process3->mustRun();

        $process4 = Process::fromShellCommandline("openssl x509");
        $process4->setInput($process3->getOutput());
        $process4->mustRun();

        @file_put_contents($path, $process2->getOutput() . $process4->getOutput());
        @chmod($path, 0666 & ~umask());

        return new PemFile($path);
    }

    /**
     * Gets the public key.
     *
     * @param string $path
     * @param string $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPublicKey(string $path, string $passPhrase): PublicKeyFile
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $process1 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nokeys -clcerts");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl x509");
        $process2->setInput($process1->getOutput());
        $process2->mustRun();

        @file_put_contents($path, $process2->getOutput());
        @chmod($path, 0666 & ~umask());

        return new PublicKeyFile($path);
    }

    /**
     * Gets the private key.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore whenever the keystore has an empty
     * pass phrase, the private key will not contain a pass phrase instead.
     *
     * @param string $path
     * @param string $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPrivateKey(string $path, string $passPhrase): PrivateKeyFile
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        // if the keystore pass phrase is an empty string, the outputted private key will not contain a pass phrase
        if (null !== $passPhrase && '' !== $passPhrase) {
            $rsaPassOut = "-passout pass:$pass -des3";
        } else {
            $rsaPassOut = '';
        }

        $process1 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nocerts -passout pass:pipe");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl rsa -passin pass:pipe $rsaPassOut");
        $process2->setInput($process1->getOutput());
        $process2->mustRun();

        @file_put_contents($path, $process2->getOutput());
        @chmod($path, 0666 & ~umask());

        return new PrivateKeyFile($path);
    }

    /**
     * Gets the public key "subject" attribute.
     *
     * @param string $passPhrase
     *
     * @return string
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getSubject(string $passPhrase): string
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $process1 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nokeys -clcerts");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline('openssl x509 -noout -subject');
        $process2->setInput($process1->getOutput());
        $process2->mustRun();

        return trim(preg_replace('/^subject=/', '', $process2->getOutput()));
    }

    /**
     * Gets the public key "issuer" attribute.
     *
     * @param string $passPhrase
     *
     * @return string
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getIssuer(string $passPhrase): string
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $process1 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nokeys -clcerts");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline('openssl x509 -noout -issuer');
        $process2->setInput($process1->getOutput());
        $process2->mustRun();

        return trim(preg_replace('/^issuer=/', '', $process2->getOutput()));
    }

    /**
     * Gets the public key "notBefore" attribute.
     *
     * @param string $passPhrase
     *
     * @return \DateTime
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getNotBefore(string $passPhrase): \DateTime
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $process1 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nokeys -clcerts");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline('openssl x509 -noout -startdate');
        $process2->setInput($process1->getOutput());
        $process2->mustRun();

        return new \DateTime(trim(preg_replace('/^notBefore=/', '', $process2->getOutput())));
    }

    /**
     * Gets the public key "notAfter" attribute.
     *
     * @param string $passPhrase
     *
     * @return \DateTime
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getNotAfter(string $passPhrase): \DateTime
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $process1 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nokeys -clcerts");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline('openssl x509 -noout -enddate');
        $process2->setInput($process1->getOutput());
        $process2->mustRun();

        return new \DateTime(trim(preg_replace('/^notAfter=/', '', $process2->getOutput())));
    }

    /**
     * Verifies a pass phrase against the keystore.
     *
     * @param string $passPhrase
     *
     * @return bool
     */
    public function verifyPassPhrase(string $passPhrase): bool
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $process = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -noout");
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * Changes the pass phrase of the keystore.
     *
     * @param string $passPhrase
     * @param string $newPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function changePassPhrase(string $passPhrase, string $newPassPhrase): KeystoreFile
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);
        $newPass = escapeshellarg($newPassPhrase);

        $process1 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nocerts -passout pass:pipe");
        $process1->mustRun();

        $process2 = Process::fromShellCommandline("openssl rsa -passin pass:pipe -passout pass:pipe");
        $process2->setInput($process1->getOutput());
        $process2->mustRun();

        $process3 = Process::fromShellCommandline("openssl pkcs12 -in $in -passin pass:$pass -nokeys -clcerts");
        $process3->mustRun();

        $process4 = Process::fromShellCommandline("openssl x509");
        $process4->setInput($process3->getOutput());
        $process4->mustRun();

        $process5 = Process::fromShellCommandline("openssl pkcs12 -passin pass:pipe -passout pass:$newPass -export");
        $process5->setInput($process2->getOutput() . $process4->getOutput());
        $process5->mustRun();

        @file_put_contents($this->getPathname(), $process5->getOutput());
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
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile
     *
     * @throws \Symfony\Component\HttpFoundation\File\Exception\FileException
     */
    public function move($directory, $name = null): KeystoreFile
    {
        $file = parent::move($directory, $name);

        return new self($file->getPathname());
    }
}
