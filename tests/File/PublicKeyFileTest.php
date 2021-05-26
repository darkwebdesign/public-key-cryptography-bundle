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

use DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile;
use PHPUnit\Framework\TestCase;

class PublicKeyFileTest extends TestCase
{
    const TEST_SUBJECT_V1_0_0_BETA1 = '/C=DE/ST=Bavaria/L=Munich/O=MIT-xperts GmbH/OU=TEST CA/CN=testbox.mit-xperts.com/emailAddress=info@mit-xperts.com';
    const TEST_SUBJECT_V1_1_0_PRE1 = 'C = DE, ST = Bavaria, L = Munich, O = MIT-xperts GmbH, OU = TEST CA, CN = testbox.mit-xperts.com, emailAddress = info@mit-xperts.com';
    const TEST_ISSUER_V1_0_0_BETA1 = '/C=DE/ST=Bavaria/L=Munich/O=MIT-xperts GmbH/OU=HBBTV-DEMO-CA/CN=itv.mit-xperts.com/emailAddress=info@mit-xperts.com';
    const TEST_ISSUER_V1_1_0_PRE1 = 'C = DE, ST = Bavaria, L = Munich, O = MIT-xperts GmbH, OU = HBBTV-DEMO-CA, CN = itv.mit-xperts.com, emailAddress = info@mit-xperts.com';
    const TEST_NOT_BEFORE = '2012-09-23 17:21:33';
    const TEST_NOT_AFTER = '2017-09-22 17:21:33';

    /** @var string */
    private $file;

    protected function setUp(): void
    {
        $this->file = tempnam(sys_get_temp_dir(), 'php');
    }

    protected function tearDown(): void
    {
        if (file_exists($this->file)) {
            unlink($this->file);
        }
    }

    /**
     * @dataProvider providerPublicKeys
     */
    public function testNewInstance(string $path): void
    {
        copy($path, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $this->assertInstanceOf(PublicKeyFile::class, $publicKeyFile);
    }

    /**
     * @dataProvider providerNotPublicKeys
     *
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     */
    public function testNewInstanceNotPublicKey(string $path): void
    {
        copy($path, $this->file);

        new PublicKeyFile($this->file);
    }

    /**
     * @dataProvider providerPublicKeys
     */
    public function testSanitize(string $path): void
    {
        copy($path, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $publicKeyFile = $publicKeyFile->sanitize();

        $this->assertInstanceOf(PublicKeyFile::class, $publicKeyFile);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testSanitizeProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        unlink($this->file);

        $publicKeyFile->sanitize();
    }

    /**
     * @dataProvider providerPublicKeysAndFormats
     */
    public function testGetFormat(string $path, string $format): void
    {
        copy($path, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $this->assertSame($format, $publicKeyFile->getFormat());
    }

    /**
     * @dataProvider providerPublicKeys
     */
    public function testGetSubject(string $path): void
    {
        copy($path, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $subject = $publicKeyFile->getSubject();

        $this->assertThat($subject, $this->logicalOr(
            $this->identicalTo(static::TEST_SUBJECT_V1_1_0_PRE1),
            $this->identicalTo(static::TEST_SUBJECT_V1_0_0_BETA1)
        ));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetSubjectProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        unlink($this->file);

        $publicKeyFile->getSubject();
    }

    /**
     * @dataProvider providerPublicKeys
     */
    public function testGetIssuer(string $path): void
    {
        copy($path, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $issuer = $publicKeyFile->getIssuer();

        $this->assertThat($issuer, $this->logicalOr(
            $this->identicalTo(static::TEST_ISSUER_V1_1_0_PRE1),
            $this->identicalTo(static::TEST_ISSUER_V1_0_0_BETA1)
        ));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetIssuerProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        unlink($this->file);

        $publicKeyFile->getIssuer();
    }

    /**
     * @dataProvider providerPublicKeys
     */
    public function testGetNotBefore(string $path): void
    {
        copy($path, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $notBefore = $publicKeyFile->getNotBefore();

        $this->assertInstanceOf(\DateTime::class, $notBefore);
        $this->assertSame(static::TEST_NOT_BEFORE, $notBefore->format('Y-m-d H:i:s'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetNotBeforeProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        unlink($this->file);

        $publicKeyFile->getNotBefore();
    }

    /**
     * @dataProvider providerPublicKeys
     */
    public function testGetNotAfter(string $path): void
    {
        copy($path, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $notAfter = $publicKeyFile->getNotAfter();

        $this->assertInstanceOf(\DateTime::class, $notAfter);
        $this->assertSame(static::TEST_NOT_AFTER, $notAfter->format('Y-m-d H:i:s'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetNotAfterProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        unlink($this->file);

        $publicKeyFile->getNotAfter();
    }

    /**
     * @dataProvider providerConvertFormat
     */
    public function testConvertFormat(string $path, string $format): void
    {
        copy($path, $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $publicKeyFile = $publicKeyFile->convertFormat($format);

        $this->assertInstanceOf(PublicKeyFile::class, $publicKeyFile);
        $this->assertSame($format, $publicKeyFile->getFormat());
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FormatNotValidException
     */
    public function testConvertFormatInvalidFormat(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $publicKeyFile->convertFormat('invalid-format');
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testConvertFormatProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        unlink($this->file);

        $publicKeyFile->convertFormat(PublicKeyFile::FORMAT_DER);
    }

    public function testMove(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', $this->file);

        $publicKeyFile = new PublicKeyFile($this->file);

        $publicKeyFile = $publicKeyFile->move($publicKeyFile->getPath(), $publicKeyFile->getFilename());

        $this->assertInstanceOf(PublicKeyFile::class, $publicKeyFile);
    }

    public function providerPublicKeys(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt'],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt'],
        ];
    }

    public function providerNotPublicKeys(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-emptypass.p12'],
            [__DIR__ . '/../Fixtures/Certificates/pem-pass.pem'],
            [__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'],
        ];
    }

    public function providerPublicKeysAndFormats(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', PublicKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', PublicKeyFile::FORMAT_DER],
        ];
    }

    public function providerConvertFormat(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', PublicKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', PublicKeyFile::FORMAT_DER],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', PublicKeyFile::FORMAT_PEM],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', PublicKeyFile::FORMAT_DER],
        ];
    }
}
