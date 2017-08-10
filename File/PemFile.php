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

use DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException;
use DarkWebDesign\PublicKeyCryptographyBundle\File\CryptoFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile;
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
     *
     * @return bool
     */
    protected function validate()
    {
        $in = escapeshellarg($this->getPathname());

        $command = "openssl x509 -in $in -noout";

        $process = new Process($command);
        $process->run();

        if (!$process->isSuccessful()) {
            return false;
        }

        $command = "openssl rsa -in $in -passin pass: -check -noout";

        $process = new Process($command);
        $process->run();

        $badPasswordRead = false !== strpos($process->getErrorOutput(), ':bad password read:');

        if (!$process->isSuccessful() && !$badPasswordRead) {
            return false;
        }

        return true;
    }

    /**
     * Creates a new PEM file from a public/private key pair.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown. Pass NULL as pass phrase if you want no
     * pass phrase on the private key instead.
     *
     * @param string $path
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile  $publicKeyFile
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile $privateKeyFile
     * @param string|null $privateKeyPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public static function create($path, PublicKeyFile $publicKeyFile, PrivateKeyFile $privateKeyFile, $privateKeyPassPhrase = null)
    {
        if ('' === $privateKeyPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $out = escapeshellarg($path);
        $publicKeyIn = escapeshellarg($publicKeyFile->getPathname());
        $publicKeyInForm = escapeshellarg($publicKeyFile->getFormat());
        $privateKeyIn = escapeshellarg($privateKeyFile->getPathname());
        $privateKeyInForm = escapeshellarg($privateKeyFile->getFormat());
        $privateKeyPass = escapeshellarg($privateKeyPassPhrase);

        if (null !== $privateKeyPassPhrase) {
            $rsaPassOut = "-passout pass:$privateKeyPass -des3";
        } else {
            $rsaPassOut = '';
        }

        $command = "
            {
                openssl x509 -in $publicKeyIn -inform $publicKeyInForm
                openssl rsa -in $privateKeyIn -inform $privateKeyInForm -passin pass:$privateKeyPass $rsaPassOut
            } > $out~ &&
            mv --force $out~ $out ||
            rm --force $out~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($path, 0666 & ~umask());

        return new self($path);
    }

    /**
     * Gets a keystore containing the public/private key pair.
     *
     * @param string $path
     * @param string $keystorePassPhrase
     * @param string|null $privateKeyPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getKeystore($path, $keystorePassPhrase, $privateKeyPassPhrase = null)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($path);
        $keystorePass = escapeshellarg($keystorePassPhrase);
        $privateKeyPass = escapeshellarg($privateKeyPassPhrase);

        $command = "
            openssl pkcs12 -in $in -passin pass:$privateKeyPass -out $out~ -passout pass:$keystorePass -export &&
            mv --force $out~ $out ||
            rm --force $out~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($path, 0666 & ~umask());

        return new KeystoreFile($path);
    }

    /**
     * Gets the public key.
     *
     * @param string $path
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPublicKey($path)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($path);

        $command = "
            openssl x509 -in $in -out $out~ &&
            mv --force $out~ $out ||
            rm --force $out~";

        $process = new Process($command);
        $process->mustRun();

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
     * @param string $path
     * @param string|null $privateKeyPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPrivateKey($path, $privateKeyPassPhrase = null)
    {
        if ('' === $privateKeyPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($path);
        $privateKeyPass = escapeshellarg($privateKeyPassPhrase);

        if (null !== $privateKeyPassPhrase) {
            $rsaPassOut = "-passout pass:$privateKeyPass -des3";
        } else {
            $rsaPassOut = '';
        }

        $command = "
            openssl rsa -in $in -passin pass:$privateKeyPass -out $out~ $rsaPassOut &&
            mv --force $out~ $out ||
            rm --force $out~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($path, 0666 & ~umask());

        return new PrivateKeyFile($path);
    }

    /**
     * Gets the public key "subject" attribute.
     *
     * @return string
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getSubject()
    {
        $in = escapeshellarg($this->getPathname());

        $command = "openssl x509 -in $in -noout -subject";

        $process = new Process($command);
        $process->mustRun();

        return trim(preg_replace('/^subject=/', '', $process->getOutput()));
    }

    /**
     * Gets the public key "issuer" attribute.
     *
     * @return string
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getIssuer()
    {
        $in = escapeshellarg($this->getPathname());

        $command = "openssl x509 -in $in -noout -issuer";

        $process = new Process($command);
        $process->mustRun();

        return trim(preg_replace('/^issuer=/', '', $process->getOutput()));
    }

    /**
     * Gets the public key "notBefore" attribute.
     *
     * @return \DateTime
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getNotBefore()
    {
        $in = escapeshellarg($this->getPathname());

        $command = "openssl x509 -in $in -noout -startdate";

        $process = new Process($command);
        $process->mustRun();

        return new \DateTime(trim(preg_replace('/^notBefore=/', '', $process->getOutput())));
    }

    /**
     * Gets the public key "notAfter" attribute.
     *
     * @return \DateTime
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getNotAfter()
    {
        $in = escapeshellarg($this->getPathname());

        $command = "openssl x509 -in $in -noout -enddate";

        $process = new Process($command);
        $process->mustRun();

        return new \DateTime(trim(preg_replace('/^notAfter=/', '', $process->getOutput())));
    }

    /**
     * Checks if the private key contains a pass phrase.
     *
     * @return bool
     */
    public function hasPassPhrase()
    {
        $in = escapeshellarg($this->getPathname());

        $command = "openssl rsa -in $in -passin pass: -check -noout";

        $process = new Process($command);
        $process->run();

        return !$process->isSuccessful();
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
    public function verifyPassPhrase($passPhrase)
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $command = "openssl rsa -in $in -passin pass:$pass -check -noout";

        $process = new Process($command);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * Adds a pass phrase to the private key.
     *
     * It is not possible to write a private key with an empty pass phrase. Therefore passing an empty string as pass
     * phrase will result in an PrivateKeyPassPhraseEmptyException being thrown.
     *
     * @param string $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function addPassPhrase($passPhrase)
    {
        if ('' === $passPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $command = "
            {
                openssl x509 -in $in
                openssl rsa -in $in -passin pass: -passout pass:$pass -des3
            } > $in~ &&
            mv --force $in~ $in ||
            rm --force $in~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
     * Removes the pass phrase from the private key.
     *
     * @param string $passPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function removePassPhrase($passPhrase)
    {
        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);

        $command = "
            {
                openssl x509 -in $in
                openssl rsa -in $in -passin pass:$pass
            } > $in~ &&
            mv --force $in~ $in ||
            rm --force $in~";

        $process = new Process($command);
        $process->mustRun();

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
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function changePassPhrase($passPhrase, $newPassPhrase)
    {
        if ('' === $newPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $pass = escapeshellarg($passPhrase);
        $newPass = escapeshellarg($newPassPhrase);

        $command = "
            {
                openssl x509 -in $in
                openssl rsa -in $in -passin pass:$pass -passout pass:$newPass -des3
            } > $in~ &&
            mv --force $in~ $in ||
            rm --force $in~";

        $process = new Process($command);
        $process->mustRun();

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
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     *
     * @throws \Symfony\Component\HttpFoundation\File\Exception\FileException
     */
    public function move($directory, $name = null)
    {
        $file = parent::move($directory, $name);

        return new self($file->getPathname());
    }
}
