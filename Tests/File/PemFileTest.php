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

class PemFileTest extends TestCase
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
     * @dataProvider providerPems
     */
    public function testNewInstance(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $this->assertInstanceOf(PemFile::class, $pemFile);
    }

    /**
     * @param string $path
     *
     * @dataProvider providerNotPems
     *
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     */
    public function testNewInstanceNotPem(string $path)
    {
        copy($path, $this->file);

        new PemFile($this->file);
    }

    /**
     * @param string $path
     * @param string|null $passPhrase
     *
     * @dataProvider providerPemsAndPassPhrases
     */
    public function testSanitize(string $path, string $passPhrase = null)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile = $pemFile->sanitize($passPhrase);

        $this->assertInstanceOf(PemFile::class, $pemFile);
        $this->assertSame(null !== $passPhrase, $pemFile->hasPassphrase());
        $this->assertTrue(null !== $passPhrase ? $pemFile->verifyPassPhrase($passPhrase) : true);
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     */
    public function testSanitizeEmptyPassPhrase()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->sanitize(static::TEST_EMPTYPASSPHRASE);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testSanitizeProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->sanitize('invalid-passphrase');
    }

    /**
     * @param string $publicKeyPath
     * @param string $privateKeyPath
     * @param string|null $privateKeyPassPhrase
     *
     * @dataProvider providerCreate
     */
    public function testCreate(string $publicKeyPath, string $privateKeyPath, string $privateKeyPassPhrase = null)
    {
        $publicKeyFile = new PublicKeyFile($publicKeyPath);
        $privateKeyFile = new PrivateKeyFile($privateKeyPath);

        $pemFile = PemFile::create($this->file, $publicKeyFile, $privateKeyFile, $privateKeyPassPhrase);

        $this->assertInstanceOf(PemFile::class, $pemFile);
        $this->assertSame(null !== $privateKeyPassPhrase, $pemFile->hasPassphrase());
        $this->assertTrue(null !== $privateKeyPassPhrase ? $pemFile->verifyPassPhrase($privateKeyPassPhrase) : true);
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     */
    public function testCreateEmptyPassPhrase()
    {
        $publicKeyFile = new PublicKeyFile(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt');
        $privateKeyFile = new PrivateKeyFile(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key');

        PemFile::create($this->file, $publicKeyFile, $privateKeyFile, static::TEST_EMPTYPASSPHRASE);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testCreateProcessFailed()
    {
        $publicKeyFile = new PublicKeyFile(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt');
        $privateKeyFile = new PrivateKeyFile(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key');

        PemFile::create($this->file, $publicKeyFile, $privateKeyFile, 'invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string|null $privateKeyPassPhrase
     *
     * @dataProvider providerPemsAndPassPhrases
     */
    public function testGetKeystore(string $path, string $privateKeyPassPhrase = null)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $keystoreFile = $pemFile->getKeystore($this->file, static::TEST_PASSPHRASE, $privateKeyPassPhrase);

        $this->assertInstanceOf(KeystoreFile::class, $keystoreFile);
        $this->assertTrue($keystoreFile->verifyPassPhrase(static::TEST_PASSPHRASE));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetKeystoreProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->getKeystore($this->file, static::TEST_PASSPHRASE, 'invalid-passphrase');
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPems
     */
    public function testGetPublicKey(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $publicKeyFile = $pemFile->getPublicKey($pemFile->getPathname());

        $this->assertInstanceOf(PublicKeyFile::class, $publicKeyFile);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetPublicKeyProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        unlink($this->file);

        $pemFile->getPublicKey($pemFile->getPathname());
    }

    /**
     * @param string $path
     * @param string|null $passPhrase
     *
     * @dataProvider providerPemsAndPassPhrases
     */
    public function testGetPrivateKey(string $path, string $passPhrase = null)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $privateKeyFile = $pemFile->getPrivateKey($pemFile->getPathname(), $passPhrase);

        $this->assertInstanceOf(PrivateKeyFile::class, $privateKeyFile);
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     */
    public function testGetPrivateKeyEmptyPassPhrase()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->getPrivateKey($pemFile->getPathname(), static::TEST_EMPTYPASSPHRASE);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetPrivateKeyProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->getPrivateKey($pemFile->getPathname(), 'invalid-passphrase');
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPems
     */
    public function testGetSubject(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $subject = $pemFile->getSubject();

        $this->assertThat($subject, $this->logicalOr(
            $this->identicalTo(static::TEST_SUBJECT_V1_1_0_PRE1),
            $this->identicalTo(static::TEST_SUBJECT_V1_0_0_BETA1)
        ));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetSubjectProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        unlink($this->file);

        $pemFile->getSubject();
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPems
     */
    public function testGetIssuer(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $issuer = $pemFile->getIssuer();

        $this->assertThat($issuer, $this->logicalOr(
            $this->identicalTo(static::TEST_ISSUER_V1_1_0_PRE1),
            $this->identicalTo(static::TEST_ISSUER_V1_0_0_BETA1)
        ));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetIssuerProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        unlink($this->file);

        $pemFile->getIssuer();
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPems
     */
    public function testGetNotBefore(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $notBefore = $pemFile->getNotBefore();

        $this->assertInstanceOf(\DateTime::class, $notBefore);
        $this->assertSame(static::TEST_NOT_BEFORE, $notBefore->format('Y-m-d H:i:s'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetNotBeforeProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        unlink($this->file);

        $pemFile->getNotBefore();
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPems
     */
    public function testGetNotAfter(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $notAfter = $pemFile->getNotAfter();

        $this->assertInstanceOf(\DateTime::class, $notAfter);
        $this->assertSame(static::TEST_NOT_AFTER, $notAfter->format('Y-m-d H:i:s'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetNotAfterProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        unlink($this->file);

        $pemFile->getNotAfter();
    }

    /**
     * @param string $path
     * @param string|null $passPhrase
     *
     * @dataProvider providerPemsAndPassPhrases
     */
    public function testHasPassPhrase(string $path, string $passPhrase = null)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $this->assertSame(null !== $passPhrase, $pemFile->hasPassphrase());
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPemsHavingPassPhrases
     */
    public function testVerifyPassPhrase(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $this->assertTrue($pemFile->verifyPassPhrase(static::TEST_PASSPHRASE));
        $this->assertFalse($pemFile->verifyPassPhrase('invalid-passphrase'));
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPemsNotHavingPassPhrases
     */
    public function testAddPassPhrase(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->addPassPhrase(static::TEST_PASSPHRASE);

        $this->assertTrue($pemFile->hasPassPhrase());
        $this->assertTrue($pemFile->verifyPassPhrase(static::TEST_PASSPHRASE));
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     */
    public function testAddPassPhraseEmptyPassPhrase()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->addPassPhrase(static::TEST_EMPTYPASSPHRASE);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testAddPassPhraseProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        unlink($this->file);

        $pemFile->addPassPhrase(static::TEST_PASSPHRASE);
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPemsHavingPassPhrases
     */
    public function testRemovePassPhrase(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->removePassPhrase(static::TEST_PASSPHRASE);

        $this->assertFalse($pemFile->hasPassPhrase());
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testRemovePassPhraseProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->removePassPhrase('invalid-passphrase');
    }

    /**
     * @param string $path
     *
     * @dataProvider providerPemsHavingPassPhrases
     */
    public function testChangePassPhrase(string $path)
    {
        copy($path, $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->changePassPhrase(static::TEST_PASSPHRASE, 'new-passphrase');

        $this->assertTrue($pemFile->hasPassPhrase());
        $this->assertTrue($pemFile->verifyPassPhrase('new-passphrase'));
    }

    /**
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\PrivateKeyPassPhraseEmptyException
     */
    public function testChangePassPhraseEmptyPassPhrase()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->changePassPhrase(static::TEST_PASSPHRASE, static::TEST_EMPTYPASSPHRASE);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testChangePassPhraseProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile->changePassPhrase('invalid-passphrase', 'new-passphrase');
    }

    public function testMove()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', $this->file);

        $pemFile = new PemFile($this->file);

        $pemFile = $pemFile->move($pemFile->getPath(), $pemFile->getFilename());

        $this->assertInstanceOf(PemFile::class, $pemFile);
    }

    /**
     * return array[]
     */
    public function providerPems(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pem-pass.pem'],
            [__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'],
        ];
    }

    /**
     * return array[]
     */
    public function providerPemsAndPassPhrases(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pem-pass.pem', static::TEST_PASSPHRASE],
            [__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'],
        ];
    }

    /**
     * return array[]
     */
    public function providerPemsHavingPassPhrases(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pem-pass.pem'],
        ];
    }

    /**
     * return array[]
     */
    public function providerPemsNotHavingPassPhrases(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pem-nopass.pem'],
        ];
    }

    /**
     * return array[]
     */
    public function providerNotPems(): array
    {
        return [
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12'],
            [__DIR__ . '/../Fixtures/Certificates/pkcs12-emptypass.p12'],
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

    /**
     * return array[]
     */
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
