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

use DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile;
use PHPUnit\Framework\TestCase;

class PrivateKeyFileTest extends TestCase
{
    const TEST_PASSWORD = 'test';

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

        new PrivateKeyFile($this->file);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerPathnamesNotPrivateKey
     *
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     */
    public function testVerifyNotPrivateKey($pathname)
    {
        copy($pathname, $this->file);

        new PrivateKeyFile($this->file);
    }

    /**
     * @param string $pathname
     * @param string $format
     * @param string|null $password
     *
     * @dataProvider providerPathnamesFormatsAndPasswords
     */
    public function testConvertFormat($pathname, $format, $password = null)
    {
        copy($pathname, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile = $privateKeyFile->convertFormat($format, $password);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile', $privateKeyFile);
        $this->assertSame($format, $privateKeyFile->getFormat());
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testConvertFormatInvalidFormat()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $format = 'invalid-format';

        $privateKeyFile->convertFormat($format);
    }

    /**
     * @param string $pathname
     * @param string|null $privateKeyPassword
     *
     * @dataProvider providerPathnamesAndPasswords
     */
    public function testHasPassphrase($pathname, $privateKeyPassword = null)
    {
        copy($pathname, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $hasPassphrase = $privateKeyFile->hasPassphrase();

        $this->assertSame(null !== $privateKeyPassword, $hasPassphrase);
    }

    public function testMove()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile = $privateKeyFile->move($privateKeyFile->getPath(), $privateKeyFile->getFilename());

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile', $privateKeyFile);
    }

    /**
     * return array[]
     */
    public function providerPathnames()
    {
        return array(
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
    public function providerPathnamesAndPasswords()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'),
        );
    }

    /**
     * return array[]
     */
    public function providerPathnamesFormatsAndPasswords()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', PrivateKeyFile::FORMAT_PEM, static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', PrivateKeyFile::FORMAT_DER, static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', PrivateKeyFile::FORMAT_DER),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', PrivateKeyFile::FORMAT_DER),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', PrivateKeyFile::FORMAT_PEM, static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', PrivateKeyFile::FORMAT_DER, static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', PrivateKeyFile::FORMAT_PEM, static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', PrivateKeyFile::FORMAT_DER, static::TEST_PASSWORD),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', PrivateKeyFile::FORMAT_DER),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', PrivateKeyFile::FORMAT_DER),
        );
    }

    /**
     * return array[]
     */
    public function providerPathnamesNotPrivateKey()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem'),
            array(__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt'),
        );
    }
}
