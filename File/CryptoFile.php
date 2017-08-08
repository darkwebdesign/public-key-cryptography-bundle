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

namespace DarkWebDesign\PublicKeyCryptographyBundle\File;

use DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException;
use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\Process\Process;

/**
 * @author Raymond Schouten
 *
 * @since 1.0
 */
abstract class CryptoFile extends File
{
    /**
     * @param string $path
     * @param bool $checkPath
     * @param bool $validateFile
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     * @throws \Symfony\Component\HttpFoundation\File\Exception\FileNotFoundException
     */
    public function __construct($path, $checkPath = true, $validateFile = true)
    {
        parent::__construct($path, $checkPath);

        if ($validateFile && !$this->validate()) {
            throw new FileNotValidException($path);
        }
    }

    /**
     * @return bool
     */
    abstract protected function validate();

    /**
     * @return bool
     */
    protected function isBinary()
    {
        $command = sprintf(
            'file --brief --mime-encoding %1$s | grep binary',
            escapeshellarg($this->getPathname())
        );

        $process = new Process($command);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * @param string $directory
     * @param string|null $name
     *
     * @return \Symfony\Component\HttpFoundation\File\File
     *
     * @throws \BadFunctionCallException
     */
    public function move($directory, $name = null)
    {
        $reflector = new \ReflectionMethod($this, 'move');
        if ($reflector->getDeclaringClass()->getName() !== get_class($this)) {
            throw new \BadFunctionCallException(sprintf('%s must override method \'move\' method.', get_class($this)));
        }

        return parent::move($directory, $name);
    }
}
