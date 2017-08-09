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

use DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\File\File;

class PublicKeyFileTest extends TestCase
{
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
     * @dataProvider providerPublicKeys
     */
    public function testNewInstance($pathname)
    {
        copy($pathname, $this->file);

        new PublicKeyFile($this->file);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerNotPublicKeys
     *
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     */
    public function testNewInstanceNotPublicKey($pathname)
    {
        copy($pathname, $this->file);

        new PublicKeyFile($this->file);
    }

    /**
     * @param string $pathname
     * @param string $format
     *
     * @dataProvider providerPublicKeysAndFormats
     */
    public function testGetFormat($pathname, $format)
    {
        copy($pathname, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $this->assertSame($format, $publicKeyFile->getFormat());
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPublicKeys
     */
    public function testGetSubject($pathname)
    {
        copy($pathname, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $this->assertSame(static::TEST_SUBJECT, $publicKeyFile->getSubject());
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPublicKeys
     */
    public function testGetIssuer($pathname)
    {
        copy($pathname, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $this->assertSame(static::TEST_ISSUER, $publicKeyFile->getIssuer());
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPublicKeys
     */
    public function testGetNotBefore($pathname)
    {
        copy($pathname, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $notBefore = $publicKeyFile->getNotBefore();

        $this->assertInstanceOf('DateTime', $notBefore);
        $this->assertSame(static::TEST_NOT_BEFORE, $notBefore->format('Y-m-d H:i:s'));
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPublicKeys
     */
    public function testGetNotAfter($pathname)
    {
        copy($pathname, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $notAfter = $publicKeyFile->getNotAfter();

        $this->assertInstanceOf('DateTime', $notAfter);
        $this->assertSame(static::TEST_NOT_AFTER, $notAfter->format('Y-m-d H:i:s'));
    }

    /**
     * @param string $pathname
     * @param string $format
     *
     * @dataProvider providerConvertFormat
     */
    public function testConvertFormat($pathname, $format)
    {
        copy($pathname, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $publicKeyFile = $publicKeyFile->convertFormat($format);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile', $publicKeyFile);
        $this->assertSame($format, $publicKeyFile->getFormat());
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FormatNotValidException
     */
    public function testConvertFormatInvalidFormat()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $publicKeyFile->convertFormat('invalid-format');
    }

    public function testMove()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $publicKeyFile = $publicKeyFile->move($publicKeyFile->getPath(), $publicKeyFile->getFilename());

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile', $publicKeyFile);
    }

    /**
     * return array[]
     */
    public function providerPublicKeys()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt'),
        );
    }

    /**
     * return array[]
     */
    public function providerNotPublicKeys()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-emptypass.p12'),
            array(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem'),
            array(__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'),
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
    public function providerPublicKeysAndFormats()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', PublicKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', PublicKeyFile::FORMAT_DER),
        );
    }

    /**
     * @return array[]
     */
    public function providerConvertFormat()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', PublicKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', PublicKeyFile::FORMAT_DER),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', PublicKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', PublicKeyFile::FORMAT_DER),
        );
    }
}
