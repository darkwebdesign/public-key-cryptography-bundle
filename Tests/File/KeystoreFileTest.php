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
     * @dataProvider providerKeystores
     */
    public function testNewInstance($path)
    {
        copy($path, $this->file);

        new KeystoreFile($this->file);
    }

    /**
     * @param string $path
     *
     * @dataProvider providerNotKeystores
     *
     * @expectedException \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     */
    public function testNewInstanceNotKeystoreFile($path)
    {
        copy($path, $this->file);

        new KeystoreFile($this->file);
    }

    /**
     * @param string $publicKeyPath
     * @param string $privateKeyPath
     * @param string|null $privateKeyPassPhrase
     *
     * @dataProvider providerCreate
     */
    public function testCreate($publicKeyPath, $privateKeyPath, $privateKeyPassPhrase = null)
    {
        $publicKeyFile = new PublicKeyFile($publicKeyPath);
        $privateKeyFile = new PrivateKeyFile($privateKeyPath);

        $keystoreFile = KeystoreFile::create($this->file, static::TEST_PASSPHRASE, $publicKeyFile, $privateKeyFile, $privateKeyPassPhrase);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\KeystoreFile', $keystoreFile);
        $this->assertTrue($keystoreFile->verifyPassPhrase(static::TEST_PASSPHRASE));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testCreateProcessFailed()
    {
        $publicKeyFile = new PublicKeyFile(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt');
        $privateKeyFile = new PrivateKeyFile(__DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key');

        KeystoreFile::create($this->file, static::TEST_PASSPHRASE, $publicKeyFile, $privateKeyFile, 'invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string $passPhrase
     *
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetPem($path, $passPhrase)
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $pemFile = $keystoreFile->getPem($this->file, $passPhrase);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PemFile', $pemFile);
        $this->assertSame(static::TEST_EMPTYPASSPHRASE !== $passPhrase, $pemFile->hasPassPhrase());
        $this->assertTrue($pemFile->verifyPassPhrase($passPhrase));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetPemProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getPem($this->file, 'invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string $passPhrase
     *
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetPublicKey($path, $passPhrase)
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $publicKeyFile = $keystoreFile->getPublicKey($this->file, $passPhrase);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PublicKeyFile', $publicKeyFile);
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetPublicKeyProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getPublicKey($this->file, 'invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string $passPhrase
     *
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetPrivateKey($path, $passPhrase)
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $privateKeyFile = $keystoreFile->getPrivateKey($this->file, $passPhrase);

        $this->assertInstanceOf('DarkWebDesign\PublicKeyCryptographyBundle\File\PrivateKeyFile', $privateKeyFile);
        $this->assertSame(static::TEST_EMPTYPASSPHRASE !== $passPhrase, $privateKeyFile->hasPassPhrase());
        $this->assertTrue($privateKeyFile->verifyPassPhrase($passPhrase));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetPrivateKeyProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getPrivateKey($this->file, 'invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string $passPhrase
     *
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetSubject($path, $passPhrase)
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
    public function testGetSubjectProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getSubject('invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string $passPhrase
     *
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetIssuer($path, $passPhrase)
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
    public function testGetIssuerProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getIssuer('invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string $passPhrase
     *
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetNotBefore($path, $passPhrase)
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $notBefore = $keystoreFile->getNotBefore($passPhrase);

        $this->assertInstanceOf('DateTime', $notBefore);
        $this->assertSame(static::TEST_NOT_BEFORE, $notBefore->format('Y-m-d H:i:s'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetNotBeforeProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getNotBefore('invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string $passPhrase
     *
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testGetNotAfter($path, $passPhrase)
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $notAfter = $keystoreFile->getNotAfter($passPhrase);

        $this->assertInstanceOf('DateTime', $notAfter);
        $this->assertSame(static::TEST_NOT_AFTER, $notAfter->format('Y-m-d H:i:s'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testGetNotAfterProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->getNotAfter('invalid-passphrase');
    }

    /**
     * @param string $path
     * @param string $passPhrase
     *
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testVerifyPassPhrase($path, $passPhrase)
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $this->assertTrue($keystoreFile->verifyPassPhrase($passPhrase));
        $this->assertFalse($keystoreFile->verifyPassPhrase('invalid-passphrase'));
    }

    /**
     * @param string $path
     * @param string $passPhrase
     *
     * @dataProvider providerKeystoresAndPassPhrases
     */
    public function testChangePassPhrase($path, $passPhrase)
    {
        copy($path, $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->changePassPhrase($passPhrase, 'new-passphrase');

        $this->assertTrue($keystoreFile->verifyPassPhrase('new-passphrase'));
    }

    /**
     * @expectedException \Symfony\Component\Process\Exception\ProcessFailedException
     */
    public function testChangePassPhraseProcessFailed()
    {
        copy(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', $this->file);

        $keystoreFile = new KeystoreFile($this->file);

        $keystoreFile->changePassPhrase('invalid-passphrase', 'new-passphrase');
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
    public function providerKeystores()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12'),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-emptypass.p12'),
        );
    }

    /**
     * return array[]
     */
    public function providerKeystoresAndPassPhrases()
    {
        return array(
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-pass.p12', static::TEST_PASSPHRASE),
            array(__DIR__ . '/../Fixtures/Certificates/pkcs12-emptypass.p12', static::TEST_EMPTYPASSPHRASE),
        );
    }

    /**
     * return array[]
     */
    public function providerNotKeystores()
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
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', static::TEST_PASSPHRASE),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', static::TEST_PASSPHRASE),
//            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', static::TEST_PASSPHRASE),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-pem.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-pass-pem.key', static::TEST_PASSPHRASE),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs1-nopass-der.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-pem.key', static::TEST_PASSPHRASE),
//            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-pass-der.key', static::TEST_PASSPHRASE),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-pem.key'),
            array(__DIR__ . '/../Fixtures/Certificates/x509-der.crt', __DIR__ . '/../Fixtures/Certificates/pkcs8-nopass-der.key'),
        );
    }
}
