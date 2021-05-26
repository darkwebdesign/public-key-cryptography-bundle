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
     * Constructs a new file from the given path.
     *
     * @throws \DarkWebDesign\PublicKeyCryptographyBundle\Exception\FileNotValidException
     * @throws \Symfony\Component\HttpFoundation\File\Exception\FileNotFoundException
     */
    public function __construct(string $path)
    {
        parent::__construct($path);

        if (!$this->validate()) {
            throw new FileNotValidException($path);
        }
    }

    /**
     * Validates that the file is actually of the correct type.
     */
    abstract protected function validate(): bool;

    /**
     * Checks if the file is binary.
     */
    protected function isBinary(): bool
    {
        $command = sprintf(
            'file --brief --mime-encoding %1$s | grep binary',
            escapeshellarg($this->getPathname())
        );

        $process = Process::fromShellCommandline($command);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * Moves the file to a new location.
     *
     * @throws \BadFunctionCallException
     */
    public function move(string $directory, string $name = null): File
    {
        $reflector = new \ReflectionMethod($this, 'move');
        if ($reflector->getDeclaringClass()->getName() !== get_class($this)) {
            throw new \BadFunctionCallException(sprintf('%s must override method \'move\' method.', get_class($this)));
        }

        return parent::move($directory, $name);
    }
}
