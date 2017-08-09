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
     * @param string $pathname
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile  $publicKeyFile
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile $privateKeyFile
     * @param string|null $privateKeyPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public static function create($pathname, PublicKeyFile $publicKeyFile, PrivateKeyFile $privateKeyFile, $privateKeyPassPhrase = null)
    {
        if ('' === $privateKeyPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $out = escapeshellarg($pathname);
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
            mv $out~ $out ||
            rm $out~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new self($pathname);
    }

    /**
     * @param string $pathname
     * @param string $keystorePassPhrase
     * @param string|null $privateKeyPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getKeystore($pathname, $keystorePassPhrase, $privateKeyPassPhrase = null)
    {
        if ('' === $privateKeyPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassPhrase);
        $privateKeyPass = escapeshellarg($privateKeyPassPhrase);

        $command = "
            openssl pkcs12 -in $in -passin pass:$privateKeyPass -out $out~ -passout pass:$keystorePass -export &&
            mv $out~ $out ||
            rm $out~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new KeystoreFile($pathname);
    }

    /**
     * @param string $pathname
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPublicKey($pathname)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);

        $command = "
            openssl x509 -in $in -out $out~ &&
            mv $out~ $out ||
            rm $out~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new PublicKeyFile($pathname);
    }

    /**
     * @param string $pathname
     * @param string|null $privateKeyPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPrivateKey($pathname, $privateKeyPassPhrase = null)
    {
        if ('' === $privateKeyPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $privateKeyPass = escapeshellarg($privateKeyPassPhrase);

        if (null !== $privateKeyPassPhrase) {
            $rsaPassOut = "-passout pass:$privateKeyPass -des3";
        } else {
            $rsaPassOut = '';
        }

        $command = "
            openssl rsa -in $in -passin pass:$privateKeyPass -out $out~ $rsaPassOut &&
            mv $out~ $out ||
            rm $out~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new PrivateKeyFile($pathname);
    }

    /**
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
            mv $in~ $in ||
            rm $in~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
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
            mv $in~ $in ||
            rm $in~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($this->getPathname(), 0666 & ~umask());
        clearstatcache(true, $this->getPathname());

        return new self($this->getPathname());
    }

    /**
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
        if ('' === $passPhrase || '' === $newPassPhrase) {
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
            mv $in~ $in ||
            rm $in~";

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
