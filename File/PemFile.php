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

        // issue: `openssl rsa` can't read PKCS#8 DER format with passphrase -> use `openssl pkcs8` as fallback
        $command = "
            openssl x509 -in $in -noout &&
            (
                error=$(openssl rsa -in $in -passin pass: -check -noout 2>&1 >/dev/null) ||
                echo \"\$error\" | grep --regexp ':bad password read:' ||
                error=$(openssl pkcs8 -in $in -passin pass: 2>&1 >/dev/null) ||
                echo \"\$error\" | grep --regexp ':bad decrypt:'
            )";

        $process = new Process($command);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * @param string                                                         $pathname
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile  $publicKeyFile
     * @param \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile $privateKeyFile
     * @param string|null                                                    $privateKeyPassword
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile
     */
    public static function create($pathname, PublicKeyFile $publicKeyFile, PrivateKeyFile $privateKeyFile, $privateKeyPassword = null)
    {
        $out = escapeshellarg($pathname);
        $publicKeyIn = escapeshellarg($publicKeyFile->getPathname());
        $publicKeyInForm = escapeshellarg($publicKeyFile->getFormat());
        $privateKeyIn = escapeshellarg($privateKeyFile->getPathname());
        $privateKeyInForm = escapeshellarg($privateKeyFile->getFormat());
        $privateKeyPass = escapeshellarg($privateKeyPassword);

        if (null !== $privateKeyPassword) {
            $rsaPassOut = "-passout pass:$privateKeyPass -des3";
        } else {
            $rsaPassOut = '';
        }

        // issue: `openssl rsa` can't read PKCS#8 DER format with passphrase -> use `openssl pkcs8` as fallback
        // issue: `openssl pkcs8` can't output RSA key with passphrase -> pipe to `openssl rsa`
        $command = "
            (
                openssl x509 -in $publicKeyIn -inform $publicKeyInForm
                openssl rsa -in $privateKeyIn -inform $privateKeyInForm -passin pass:$privateKeyPass $rsaPassOut ||
                openssl pkcs8 -in $privateKeyIn -inform $privateKeyInForm -passin pass:$privateKeyPass |
                openssl rsa $rsaPassOut
            ) > $out~ &&
            mv $out~ $out";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new self($pathname);
    }

    /**
     * @param string      $pathname
     * @param string      $keystorePassword
     * @param string|null $privateKeyPassword
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile
     */
    public function getKeystore($pathname, $keystorePassword, $privateKeyPassword = null)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $keystorePass = escapeshellarg($keystorePassword);
        $privateKeyPass = escapeshellarg($privateKeyPassword);

        $command = "
            openssl pkcs12 -in $in -passin pass:$privateKeyPass -out $out~ -passout pass:$keystorePass -export &&
            mv $out~ $out";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new KeystoreFile($pathname);
    }

    /**
     * @param string $pathname
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile
     */
    public function getPublicKey($pathname)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);

        $command = "
            openssl x509 -in $in -out $out~ &&
            mv $out~ $out";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new PublicKeyFile($pathname);
    }

    /**
     * @param string      $pathname
     * @param string|null $privateKeyPassword
     *
     * @return \DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile
     */
    public function getPrivateKey($pathname, $privateKeyPassword = null)
    {
        $in = escapeshellarg($this->getPathname());
        $out = escapeshellarg($pathname);
        $privateKeyPass = escapeshellarg($privateKeyPassword);

        if (null !== $privateKeyPassword) {
            $rsaPassOut = "-passout pass:$privateKeyPass -des3";
        } else {
            $rsaPassOut = '';
        }

        $command = "
            openssl rsa -in $in -passin pass:$privateKeyPass -out $out~ $rsaPassOut &&
            mv $out~ $out";

        $process = new Process($command);
        $process->mustRun();

        @chmod($pathname, 0666 & ~umask());

        return new PrivateKeyFile($pathname);
    }

    /**
     * @return string
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
