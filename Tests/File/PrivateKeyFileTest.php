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
    const TEST_EMPTYPASSWORD = '';

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
     * @dataProvider providerPrivateKeys
     */
    public function testNewInstance($pathname)
    {
        copy($pathname, $this->file);

        new PrivateKeyFile($this->file);
    }

    /**
     * @param string $pathname
     *
     * @dataProvider providerNotPrivateKeys
     *
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     */
    public function testNewInstanceNotPrivateKey($pathname)
    {
        copy($pathname, $this->file);

        new PrivateKeyFile($this->file);
    }

    /**
     * @param string $pathname
     * @param string $format
     *
     * @dataProvider providerPrivateKeysAndFormats
     */
    public function testGetFormat($pathname, $format)
    {
        copy($pathname, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $this->assertSame($format, $privateKeyFile->getFormat());
    }

    /**
     * @param string $pathname
     * @param string $format
     * @param string|null $passPhrase
     *
     * @dataProvider providerConvertFormat
     */
    public function testConvertFormat($pathname, $format, $passPhrase = null)
    {
        copy($pathname, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile = $privateKeyFile->convertFormat($format, $passPhrase);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile', $privateKeyFile);
        $this->assertSame($format, $privateKeyFile->getFormat());
        $this->assertSame(null !== $passPhrase, $privateKeyFile->hasPassPhrase());
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FormatNotValidException
     */
    public function testConvertFormatInvalidFormat()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->convertFormat('invalid-format');
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     */
    public function testConvertFormatEmptyPassPhrase()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->convertFormat(PrivateKeyFile::FORMAT_DER, static::TEST_EMPTYPASSWORD);
    }

    /**
     * @param string $pathname
     * @param bool $privateKeyHasPassphrase
     *
     * @dataProvider providerHasPassPhrase
     */
    public function testHasPassPhrase($pathname, $hasPassphrase)
    {
        copy($pathname, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $this->assertSame($hasPassphrase, $privateKeyFile->hasPassphrase());
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
    public function providerPrivateKeys()
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
    public function providerPrivateKeysAndFormats()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', PrivateKeyFile::FORMAT_DER),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', PrivateKeyFile::FORMAT_DER),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', PrivateKeyFile::FORMAT_DER),
        );
    }

    /**
     * return array[]
     */
    public function providerNotPrivateKeys()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-emptypass.p12'),
            array(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem'),
            array(__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt'),
        );
    }

    /**
     * return array[]
     */
    public function providerConvertFormat()
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
    public function providerHasPassPhrase()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', true),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', false),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', false),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', true),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', true),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', false),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', false),
        );
    }
}
