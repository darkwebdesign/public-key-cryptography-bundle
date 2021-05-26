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

use DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile;
use DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile;
use PHPUnit\Framework\TestCase;

class KeystoreFileTest extends TestCase
{
    const TEST_PASSPHRASE = 'test';
    const TEST_EMPTYPASSPHRASE = '';
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
     * @dataProvider providerKeystores
     */
    public function testNewInstance(string $path): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $this->assertInstanceOf(KeystoreFile::class, $keystoreFile);
    }

    /**
     * @dataProvider providerNotKeystores
     *
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     */
    public function testNewInstanceNotKeystoreFile(string $path): void
    {
        copy($path, $this->file);

        new KeystoreFile($this->file);
    }

    /**
     * @dataProvider providerCreate
     */
    public function testCreate(string $publicKeyPath, string $privateKeyPath, string $privateKeyPassPhrase = null): void
    {
        $publicKeyFile = new PublicKeyFile($publicKeyPath);
        $privateKeyFile = new PrivateKeyFile($privateKeyPath);

        $keystoreFile = KeystoreFile::create($this->file, static::TEST_PASSPHRASE, $publicKeyFile, $privateKeyFile, $privateKeyPassPhrase);

        $this->assertInstanceOf(KeystoreFile::class, $keystoreFile);
        $this->assertTrue($keystoreFile->verifyPassPhrase(static::TEST_PASSPHRASE));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testCreateProcessFailed(): void
    {
        $publicKeyFile = new PublicKeyFile(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt');
        $privateKeyFile = new PrivateKeyFile(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key');

        KeystoreFile::create($this->file, static::TEST_PASSPHRASE, $publicKeyFile, $privateKeyFile, 'invalid-passphrase');
    }

    /**
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetPem(string $path, string $passPhrase): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $pemFile = $keystoreFile->getPem($this->file, $passPhrase);

        $this->assertInstanceOf(PemFile::class, $pemFile);
        $this->assertSame(static::TEST_EMPTYPASSPHRASE !== $passPhrase, $pemFile->hasPassPhrase());
        $this->assertTrue($pemFile->verifyPassPhrase($passPhrase));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetPemProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getPem($this->file, 'invalid-passphrase');
    }

    /**
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetPublicKey(string $path, string $passPhrase): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $publicKeyFile = $keystoreFile->getPublicKey($this->file, $passPhrase);

        $this->assertInstanceOf(PublicKeyFile::class, $publicKeyFile);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetPublicKeyProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getPublicKey($this->file, 'invalid-passphrase');
    }

    /**
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetPrivateKey(string $path, string $passPhrase): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $privateKeyFile = $keystoreFile->getPrivateKey($this->file, $passPhrase);

        $this->assertInstanceOf(PrivateKeyFile::class, $privateKeyFile);
        $this->assertSame(static::TEST_EMPTYPASSPHRASE !== $passPhrase, $privateKeyFile->hasPassPhrase());
        $this->assertTrue($privateKeyFile->verifyPassPhrase($passPhrase));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetPrivateKeyProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getPrivateKey($this->file, 'invalid-passphrase');
    }

    /**
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetSubject(string $path, string $passPhrase): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $subject = $keystoreFile->getSubject($passPhrase);

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
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getSubject('invalid-passphrase');
    }

    /**
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetIssuer(string $path, string $passPhrase): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $issuer = $keystoreFile->getIssuer($passPhrase);

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
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getIssuer('invalid-passphrase');
    }

    /**
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetNotBefore(string $path, string $passPhrase): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $notBefore = $keystoreFile->getNotBefore($passPhrase);

        $this->assertInstanceOf(\DateTime::class, $notBefore);
        $this->assertSame(static::TEST_NOT_BEFORE, $notBefore->format('Y-m-d H:i:s'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetNotBeforeProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getNotBefore('invalid-passphrase');
    }

    /**
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetNotAfter(string $path, string $passPhrase): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $notAfter = $keystoreFile->getNotAfter($passPhrase);

        $this->assertInstanceOf(\DateTime::class, $notAfter);
        $this->assertSame(static::TEST_NOT_AFTER, $notAfter->format('Y-m-d H:i:s'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetNotAfterProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getNotAfter('invalid-passphrase');
    }

    /**
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testVerifyPassPhrase(string $path, string $passPhrase): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $this->assertTrue($keystoreFile->verifyPassPhrase($passPhrase));
        $this->assertFalse($keystoreFile->verifyPassPhrase('invalid-passphrase'));
    }

    /**
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testChangePassPhrase(string $path, string $passPhrase): void
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->changePassPhrase($passPhrase, 'new-passphrase');

        $this->assertTrue($keystoreFile->verifyPassPhrase('new-passphrase'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testChangePassPhraseProcessFailed(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->changePassPhrase('invalid-passphrase', 'new-passphrase');
    }

    public function testMove(): void
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile = $keystoreFile->move($keystoreFile->getPath(), $keystoreFile->getFilename());

        $this->assertInstanceOf(KeystoreFile::class, $keystoreFile);
    }

    public function providerKeystores(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-emptypass.p12'],
        ];
    }

    public function providerKeystoresAndPassPhrases(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-emptypass.p12', static::TEST_EMPTYPASSPHRASE],
        ];
    }

    public function providerNotKeystores(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pem-pass.pem'],
            [__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'],
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt'],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'],
        ];
    }

    public function providerCreate(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', static::TEST_PASSPHRASE],
//            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', static::TEST_PASSPHRASE],
//            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'],
            [__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'],
        ];
    }
}
