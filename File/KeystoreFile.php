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
use DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile;
use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\Process\Process;

/**
 * @author Raymond Schouten
 *
 * @since 1.0
 */
class KeystoreFile extends CryptoFile
{
    /**
     * @return bool
     */
    protected function validate()
    {
        $in = escapeshellarg($this->getPathname());

        $command = "openssl pkcs12 -in $in -passin pass: -noout";

        $process = new Process($command);
        $process->run();

        $invalidPassword = false !== strpos($process->getErrorOutput(), 'invalid password');

        if (!$process->isSuccessful() && !$invalidPassword) {
            return false;
        }

        return true;
    }

    /**
     * @param string $pathname
     * @param string $keystorePassPhrase
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile $publicKeyFile
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile $privateKeyFile
     * @param string|null $privateKeyPassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public static function create($pathname, $keystorePassPhrase, PublicKeyFile $publicKeyFile, PrivateKeyFile $privateKeyFile, $privateKeyPassPhrase = null)
    {
        if ('' === $privateKeyPassPhrase) {
            throw new PrivateKeyPassPhraseEmptyException();
        }

        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassPhrase);
        $publicKeyIn = escapeshellarg($publicKeyFile->getPathname());
        $publicKeyInForm = escapeshellarg($publicKeyFile->getFormat());
        $privateKeyIn = escapeshellarg($privateKeyFile->getPathname());
        $privateKeyInForm = escapeshellarg($privateKeyFile->getFormat());
        $privateKeyPass = escapeshellarg($privateKeyPassPhrase);

        $command = "
            {
                openssl rsa -in $privateKeyIn -inform $privateKeyInForm -passin pass:$privateKeyPass -passout pass:pipe -des3
                openssl x509 -in $publicKeyIn -inform $publicKeyInForm
            } |
            openssl pkcs12 -passin pass:pipe -out $out~ -passout pass:$keystorePass -export &&
            mv $out~ $out ||
            rm $out~";

        $process = new Process($command);
        $process->mustRun();

        return new self($pathname);
    }

    /**
     * @param string $pathname
     * @param string $keystorePassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPem($pathname, $keystorePassPhrase)
    {
        // if the keystore pass phrase is an empty string, the outputted private key will not contain a pass phrase
        $privateKeyPassPhrase = '' !== $keystorePassPhrase ? $keystorePassPhrase : null;

        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassPhrase);

        if (null !== $privateKeyPassPhrase) {
            $rsaPassOut = "-passout pass:$privateKeyPassPhrase -des3";
        } else {
            $rsaPassOut = '';
        }

        $command = "
            {
                openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
                openssl x509
                openssl pkcs12 -in $in -passin pass:$keystorePass -nocerts -passout pass:pipe |
                openssl rsa -passin pass:pipe $rsaPassOut
            } > $out~ &&
            mv $out~ $out ||
            rm $out~";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new PemFile($pathname);
    }

    /**
     * @param string $pathname
     * @param string $keystorePassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPublicKey($pathname, $keystorePassPhrase)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassPhrase);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
            openssl x509 -out $out~ &&
            mv $out~ $out";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new PublicKeyFile($pathname);
    }

    /**
     * @param string $pathname
     * @param string $keystorePassPhrase
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getPrivateKey($pathname, $keystorePassPhrase)
    {
        // if the keystore pass phrase is an empty string, the outputted private key will not contain a pass phrase
        $privateKeyPassPhrase = '' !== $keystorePassPhrase ? $keystorePassPhrase : null;

        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassPhrase);

        if (null !== $privateKeyPassPhrase) {
            $rsaPassOut = "-passout pass:$privateKeyPassPhrase -des3";
        } else {
            $rsaPassOut = '';
        }

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nocerts -passout pass:pipe |
            openssl rsa -passin pass:pipe -out $out~ $rsaPassOut &&
            mv $out~ $out";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new PrivateKeyFile($pathname);
    }

    /**
     * @param string $keystorePassPhrase
     *
     * @return string
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getSubject($keystorePassPhrase)
    {
        $in = escapeshellarg($this->getPathname());
        $keystorePass = escapeshellarg($keystorePassPhrase);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
            openssl x509 -noout -subject";

        $process = new Process($command);
        $process->mustRun();

        return trim(preg_replace('/^subject=/', '', $process->getOutput()));
    }

    /**
     * @param string $keystorePassPhrase
     *
     * @return string
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getIssuer($keystorePassPhrase)
    {
        $in = escapeshellarg($this->getPathname());
        $keystorePass = escapeshellarg($keystorePassPhrase);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
            openssl x509 -noout -issuer";

        $process = new Process($command);
        $process->mustRun();

        return trim(preg_replace('/^issuer=/', '', $process->getOutput()));
    }

    /**
     * @param string $keystorePassPhrase
     *
     * @return \DateTime
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getNotBefore($keystorePassPhrase)
    {
        $in = escapeshellarg($this->getPathname());
        $keystorePass = escapeshellarg($keystorePassPhrase);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
            openssl x509 -noout -startdate";

        $process = new Process($command);
        $process->mustRun();

        return new \DateTime(trim(preg_replace('/^notBefore=/', '', $process->getOutput())));
    }

    /**
     * @param string $keystorePassPhrase
     *
     * @return \DateTime
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function getNotAfter($keystorePassPhrase)
    {
        $in = escapeshellarg($this->getPathname());
        $keystorePass = escapeshellarg($keystorePassPhrase);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
            openssl x509 -noout -enddate";

        $process = new Process($command);
        $process->mustRun();

        return new \DateTime(trim(preg_replace('/^notAfter=/', '', $process->getOutput())));
    }

    /**
     * @param string $directory
     * @param string|null $name
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile
     *
     * @throws \Symfony\Component\HttpFoundation\File\Exception\FileException
     */
    public function move($directory, $name = null)
    {
        $file = parent::move($directory, $name);

        return new self($file->getPathname());
    }
}
