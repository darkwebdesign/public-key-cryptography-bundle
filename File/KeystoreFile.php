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

        $command = "openssl pkcs12 -in $in -passin pass:";

        $process = new Process($command);
        $process->run();

        $invalidPassword = false !== strpos($process->getErrorOutput(), 'invalid password');

        return $process->isSuccessful() || $invalidPassword;
    }

    /**
     * @param string $pathname
     * @param string $keystorePassword
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile  $publicKeyFile
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile $privateKeyFile
     * @param string|null $privateKeyPassword
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile
     */
    public static function create($pathname, $keystorePassword, PublicKeyFile $publicKeyFile, PrivateKeyFile $privateKeyFile, $privateKeyPassword = null)
    {
        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassword);
        $publicKeyIn = escapeshellarg($publicKeyFile->getPathname());
        $publicKeyInForm = escapeshellarg($publicKeyFile->getFormat());
        $privateKeyIn = escapeshellarg($privateKeyFile->getPathname());
        $privateKeyInForm = escapeshellarg($privateKeyFile->getFormat());
        $privateKeyPass = escapeshellarg($privateKeyPassword);

        if (null !== $privateKeyPassword) {
            $rsaPassOut = "-passout pass:$privateKeyPass -des3";
            $pkcs8PassInNoCrypt = "-passin pass:$privateKeyPass";
        } else {
            $rsaPassOut = '';
            $pkcs8PassInNoCrypt = ' -nocrypt';
        }

        // issue: `openssl pkcs12` requires key first for piped input
        $command = "
            (
                openssl rsa -in $privateKeyIn -inform $privateKeyInForm -passin pass:$privateKeyPass $rsaPassOut ||
                openssl pkcs8 -in $privateKeyIn -inform $privateKeyInForm $pkcs8PassInNoCrypt |
                openssl rsa $rsaPassOut
                openssl x509 -in $publicKeyIn -inform $publicKeyInForm
            ) |
            openssl pkcs12 -passin pass:$privateKeyPass -out $out~ -passout pass:$keystorePass -export &&
            mv $out~ $out";

        $process = new Process($command);
        $process->mustRun();

        return new self($pathname);
    }

    /**
     * @param string $pathname
     * @param string $keystorePassword
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     */
    public function getPem($pathname, $keystorePassword)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassword);

        $command = "
            (
                openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
                openssl x509
                openssl pkcs12 -in $in -passin pass:$keystorePass -nocerts -passout pass:pipe |
                openssl rsa -passin pass:pipe -passout pass:$keystorePass -des3
            ) > $out~ &&
            mv $out~ $out";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new PemFile($pathname);
    }

    /**
     * @param string $pathname
     * @param string $keystorePassword
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile
     */
    public function getPublicKey($pathname, $keystorePassword)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassword);

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
     * @param string $keystorePassword
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     */
    public function getPrivateKey($pathname, $keystorePassword)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassword);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nocerts -passout pass:pipe |
            openssl rsa -passin pass:pipe -out $out~ -passout pass:$keystorePass -des3 &&
            mv $out~ $out";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new PrivateKeyFile($pathname);
    }

    /**
     * @param string $keystorePassword
     *
     * @return string
     */
    public function getSubject($keystorePassword)
    {
        $in = escapeshellarg($this->getPathname());
        $keystorePass = escapeshellarg($keystorePassword);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
            openssl x509 -noout -subject";

        $process = new Process($command);
        $process->mustRun();

        return trim(ltrim($process->getOutput(), 'subject='));
    }

    /**
     * @param string $keystorePassword
     *
     * @return string
     */
    public function getIssuer($keystorePassword)
    {
        $in = escapeshellarg($this->getPathname());
        $keystorePass = escapeshellarg($keystorePassword);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
            openssl x509 -noout -issuer";

        $process = new Process($command);
        $process->mustRun();

        return trim(ltrim($process->getOutput(), 'issuer='));
    }

    /**
     * @param string $keystorePassword
     *
     * @return \DateTime
     */
    public function getNotBefore($keystorePassword)
    {
        $in = escapeshellarg($this->getPathname());
        $keystorePass = escapeshellarg($keystorePassword);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
            openssl x509 -noout -startdate";

        $process = new Process($command);
        $process->mustRun();

        return new \DateTime(trim(ltrim($process->getOutput(), 'notBefore=')));
    }

    /**
     * @param string $keystorePassword
     *
     * @return \DateTime
     */
    public function getNotAfter($keystorePassword)
    {
        $in = escapeshellarg($this->getPathname());
        $keystorePass = escapeshellarg($keystorePassword);

        $command = "
            openssl pkcs12 -in $in -passin pass:$keystorePass -nokeys |
            openssl x509 -noout -enddate";

        $process = new Process($command);
        $process->mustRun();

        return new \DateTime(trim(ltrim($process->getOutput(), 'notAfter=')));
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
