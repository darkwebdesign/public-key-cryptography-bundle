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

namespace DarkWebDesign\PublicKeyCryptographyBundle\Tests\File;

use DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\File\File;

class KeystoreFileTest extends TestCase
{
    const TEST_PASSWORD = 'test';
    const TEST_SUBJECT = '/C=DE/ST=Bavaria/L=Munich/O=MIT-xperts GmbH/OU=TEST CA/CN=testbox.mit-xperts.com/emailAddress=info@mit-xperts.com';
    const TEST_ISSUER = '/C=DE/ST=Bavaria/L=Munich/O=MIT-xperts GmbH/OU=HBBTV-DEMO-CA/CN=itv.mit-xperts.com/emailAddress=info@mit-xperts.com';
    const TEST_NOT_BEFORE = '2012-09-23 17:21:33';
    const TEST_NOT_AFTER = '2017-09-22 17:21:33';

    /** @var string */
    private $file;

    protected function setUp()
    {
        $this->file = tempnam(sys_get_temp_dir(), 'php');
    }

    protected function tearDown()
    {
        if (file_exists($this->file)) {
            unlink($this->file);
        }
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnames
     */
    public function testNewInstance($pathname)
    {
        copy($pathname, $this->file);

        new File($this->file);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnamesNotKeystoreFile
     */
    public function testNewInstanceNotKeystoreFile($pathname)
    {
        copy($pathname, $this->file);

        new File($this->file);
    }

    /**
     * @param string $publicKeyPathname
     * @param string $privateKeyPathname
     * @param string|null $privateKeyPassword
     *
     * @dataProvider providerCreate
     */
    public function testCreate($publicKeyPathname, $privateKeyPathname, $privateKeyPassword = null)
    {
        $publicKeyFile = new PublicKeyFile($publicKeyPathname);
        $privateKeyFile = new PrivateKeyFile($privateKeyPathname);

        $keystoreFile = KeystoreFile::create($this->file, static::TEST_PASSWORD, $publicKeyFile, $privateKeyFile, $privateKeyPassword);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile', $keystoreFile);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnames
     */
    public function testGetPem($pathname)
    {
        copy($pathname, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $pemFile = $keystoreFile->getPem($keystoreFile->getPathname(), static::TEST_PASSWORD);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile', $pemFile);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnames
     */
    public function testGetPublicKey($pathname)
    {
        copy($pathname, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $publicKeyFile = $keystoreFile->getPublicKey($keystoreFile->getPathname(), static::TEST_PASSWORD);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile', $publicKeyFile);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnames
     */
    public function testGetPrivateKey($pathname)
    {
        copy($pathname, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $privateKeyFile = $keystoreFile->getPrivateKey($keystoreFile->getPathname(), static::TEST_PASSWORD);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile', $privateKeyFile);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnames
     */
    public function testGetSubject($pathname)
    {
        copy($pathname, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $subject = $keystoreFile->getSubject(static::TEST_PASSWORD);

        $this->assertSame(static::TEST_SUBJECT, $subject);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnames
     */
    public function testGetIssuer($pathname)
    {
        copy($pathname, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $issuer = $keystoreFile->getIssuer(static::TEST_PASSWORD);

        $this->assertSame(static::TEST_ISSUER, $issuer);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnames
     */
    public function testGetNotBefore($pathname)
    {
        copy($pathname, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $notBefore = $keystoreFile->getNotBefore(static::TEST_PASSWORD);

        $this->assertInstanceOf('DateTime', $notBefore);
        $this->assertSame(static::TEST_NOT_BEFORE, $notBefore->format('Y-m-d H:i:s'));
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnames
     */
    public function testGetNotAfter($pathname)
    {
        copy($pathname, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $notAfter = $keystoreFile->getNotAfter(static::TEST_PASSWORD);

        $this->assertInstanceOf('DateTime', $notAfter);
        $this->assertSame(static::TEST_NOT_AFTER, $notAfter->format('Y-m-d H:i:s'));
    }

    public function testMove()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile = $keystoreFile->move($keystoreFile->getPath(), $keystoreFile->getFilename());

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile', $keystoreFile);
    }

    /**
     * return array[]
     */
    public function providerPathnames()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12'),
        );
    }

    /**
     * return array[]
     */
    public function providerPathnamesNotKeystoreFile()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem'),
            array(__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'),
        );
    }

    /**
     * return array[]
     */
    public function providerCreate()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'),
        );
    }
}
