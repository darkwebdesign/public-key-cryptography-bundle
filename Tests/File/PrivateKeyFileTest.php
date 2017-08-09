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
    const TEST_PASSPHRASE = 'test';
    const TEST_EMPTYPASSPHRASE = '';

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
     * @param string $path
     *
     * @dataProvider providerPrivateKeys
     */
    public function testNewInstance($path)
    {
        copy($path, $this->file);

        new PrivateKeyFile($this->file);
    }

    /**
     * @param string $path
     *
     * @dataProvider providerNotPrivateKeys
     *
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     */
    public function testNewInstanceNotPrivateKey($path)
    {
        copy($path, $this->file);

        new PrivateKeyFile($this->file);
    }

    /**
     * @param string $path
     * @param string $format
     *
     * @dataProvider providerPrivateKeysAndFormats
     */
    public function testGetFormat($path, $format)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $this->assertSame($format, $privateKeyFile->getFormat());
    }

    /**
     * @param string $path
     * @param string $format
     * @param string|null $passPhrase
     *
     * @dataProvider providerConvertFormat
     */
    public function testConvertFormat($path, $format, $passPhrase = null)
    {
        copy($path, $this->file);

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

        $privateKeyFile->convertFormat(PrivateKeyFile::FORMAT_DER, static::TEST_EMPTYPASSPHRASE);
    }

    /**
     * @param string $path
     * @param bool $privateKeyHasPassphrase
     *
     * @dataProvider providerHasPassPhrase
     */
    public function testHasPassPhrase($path, $hasPassphrase)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $this->assertSame($hasPassphrase, $privateKeyFile->hasPassphrase());
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPrivateKeysHavingPassPhrases
     */
    public function testVerifyPassPhrase($path)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $verified = $privateKeyFile->verifyPassPhrase(static::TEST_PASSPHRASE);

        $this->assertTrue($verified);

        $verified = $privateKeyFile->verifyPassPhrase('invalid-passphrase');

        $this->assertFalse($verified);
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPrivateKeysNotHavingPassPhrases
     */
    public function testAddPassPhrase($path)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->addPassPhrase(static::TEST_PASSPHRASE);

        $verified = $privateKeyFile->verifyPassPhrase(static::TEST_PASSPHRASE);

        $this->assertTrue($verified);
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     */
    public function testAddPassPhraseEmptyPassPhrase()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->addPassPhrase(static::TEST_EMPTYPASSPHRASE);
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPrivateKeysHavingPassPhrases
     */
    public function testRemovePassPhrase($path)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->removePassPhrase(static::TEST_PASSPHRASE);

        $this->assertFalse($privateKeyFile->hasPassPhrase());
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPrivateKeysHavingPassPhrases
     */
    public function testChangePassPhrase($path)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->changePassPhrase(static::TEST_PASSPHRASE, 'new-passphrase');

        $verified = $privateKeyFile->verifyPassPhrase('new-passphrase');

        $this->assertTrue($verified);
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     */
    public function testChangePassPhraseEmptyPassPhrase()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->changePassPhrase(static::TEST_PASSPHRASE, static::TEST_EMPTYPASSPHRASE);
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
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key'),
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
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', PrivateKeyFile::FORMAT_DER),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', PrivateKeyFile::FORMAT_DER),
        );
    }

    /**
     * @return array[]
     */
    public function providerPrivateKeysHavingPassPhrases()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key'),
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key'),
        );
    }

    /**
     * @return array[]
     */
    public function providerPrivateKeysNotHavingPassPhrases()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'),
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'),
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'),
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
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', PrivateKeyFile::FORMAT_PEM, static::TEST_PASSPHRASE),
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', PrivateKeyFile::FORMAT_DER, static::TEST_PASSPHRASE),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', PrivateKeyFile::FORMAT_DER),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', PrivateKeyFile::FORMAT_PEM),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', PrivateKeyFile::FORMAT_DER),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', PrivateKeyFile::FORMAT_PEM, static::TEST_PASSPHRASE),
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', PrivateKeyFile::FORMAT_DER, static::TEST_PASSPHRASE),
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', PrivateKeyFile::FORMAT_PEM, static::TEST_PASSPHRASE),
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', PrivateKeyFile::FORMAT_DER, static::TEST_PASSPHRASE),
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
//            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', true),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', false),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', false),
        );
    }
}
