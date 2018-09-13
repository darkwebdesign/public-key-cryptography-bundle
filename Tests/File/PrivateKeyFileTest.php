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

declare(strict_types=1);

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
    public function testNewInstance(string $path)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $this->assertInstanceOf(PrivateKeyFile::class, $privateKeyFile);
    }

    /**
     * @param string $path
     *
     * @dataProvider providerNotPrivateKeys
     *
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     */
    public function testNewInstanceNotPrivateKey(string $path)
    {
        copy($path, $this->file);

        new PrivateKeyFile($this->file);
    }

    /**
     * @param string $path
     * @param string|null $passPhrase
     *
     * @dataProvider providerPrivateKeysAndPassPhrases
     */
    public function testSanitize(string $path, string $passPhrase = null)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile = $privateKeyFile->sanitize($passPhrase);

        $this->assertInstanceOf(PrivateKeyFile::class, $privateKeyFile);
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     */
    public function testSanitizeEmptyPassPhrase()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->sanitize(static::TEST_EMPTYPASSPHRASE);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testSanitizeProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->sanitize('invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string $format
     *
     * @dataProvider providerPrivateKeysAndFormats
     */
    public function testGetFormat(string $path, string $format)
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
    public function testConvertFormat(string $path, string $format, string $passPhrase = null)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile = $privateKeyFile->convertFormat($format, $passPhrase);

        $this->assertInstanceOf(PrivateKeyFile::class, $privateKeyFile);
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
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testConvertFormatProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->convertFormat(PrivateKeyFile::FORMAT_DER, 'invalid-passphrase');
    }

    /**
     * @param string $path
     * @param bool $hasPassphrase
     *
     * @dataProvider providerHasPassPhrase
     */
    public function testHasPassPhrase(string $path, bool $hasPassphrase)
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
    public function testVerifyPassPhrase(string $path)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $this->assertTrue($privateKeyFile->verifyPassPhrase(static::TEST_PASSPHRASE));
        $this->assertFalse($privateKeyFile->verifyPassPhrase('invalid-passphrase'));
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPrivateKeysNotHavingPassPhrases
     */
    public function testAddPassPhrase(string $path)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->addPassPhrase(static::TEST_PASSPHRASE);

        $this->assertTrue($privateKeyFile->hasPassPhrase());
        $this->assertTrue($privateKeyFile->verifyPassPhrase(static::TEST_PASSPHRASE));
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
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testAddPassPhraseProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        unlink($this->file);

        $privateKeyFile->addPassPhrase(static::TEST_PASSPHRASE);
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPrivateKeysHavingPassPhrases
     */
    public function testRemovePassPhrase(string $path)
    {
        copy($path, $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->removePassPhrase(static::TEST_PASSPHRASE);

        $this->assertFalse($privateKeyFile->hasPassPhrase());
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testRemovePassPhraseProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->removePassPhrase('invalid-passphrase');
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPrivateKeysHavingPassPhrases
     */
    public function testChangePassPhrase(string $path)
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

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testChangePassPhraseProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile->changePassPhrase('invalid-passphrase', 'new-passphrase');
    }

    public function testMove()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', $this->file);

        $privateKeyFile = new PrivateKeyFile($this->file);

        $privateKeyFile = $privateKeyFile->move($privateKeyFile->getPath(), $privateKeyFile->getFilename());

        $this->assertInstanceOf(PrivateKeyFile::class, $privateKeyFile);
    }

    /**
     * return array[]
     */
    public function providerPrivateKeys(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key'],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'],
        ];
    }

    /**
     * return array[]
     */
    public function providerPrivateKeysAndPassPhrases(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', static::TEST_PASSPHRASE],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'],
        ];
    }

    /**
     * return array[]
     */
    public function providerPrivateKeysAndFormats(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', PrivateKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', PrivateKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', PrivateKeyFile::FORMAT_DER],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', PrivateKeyFile::FORMAT_PEM],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', PrivateKeyFile::FORMAT_DER],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', PrivateKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', PrivateKeyFile::FORMAT_DER],
        ];
    }

    /**
     * @return array[]
     */
    public function providerPrivateKeysHavingPassPhrases(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key'],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key'],
        ];
    }

    /**
     * @return array[]
     */
    public function providerPrivateKeysNotHavingPassPhrases(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'],
        ];
    }

    /**
     * return array[]
     */
    public function providerNotPrivateKeys(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-emptypass.p12'],
            [__DIR__ . '/../Fixtures/Certificates/pem-pass.pem'],
            [__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'],
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt'],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt'],
        ];
    }

    /**
     * return array[]
     */
    public function providerConvertFormat(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', PrivateKeyFile::FORMAT_PEM, static::TEST_PASSPHRASE],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', PrivateKeyFile::FORMAT_DER, static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', PrivateKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', PrivateKeyFile::FORMAT_DER],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', PrivateKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', PrivateKeyFile::FORMAT_DER],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', PrivateKeyFile::FORMAT_PEM, static::TEST_PASSPHRASE],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', PrivateKeyFile::FORMAT_DER, static::TEST_PASSPHRASE],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', PrivateKeyFile::FORMAT_PEM, static::TEST_PASSPHRASE],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', PrivateKeyFile::FORMAT_DER, static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', PrivateKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', PrivateKeyFile::FORMAT_DER],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', PrivateKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', PrivateKeyFile::FORMAT_DER],
        ];
    }

    /**
     * return array[]
     */
    public function providerHasPassPhrase(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', true],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key', false],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key', false],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', true],
//            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', true],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key', false],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key', false],
        ];
    }
}
