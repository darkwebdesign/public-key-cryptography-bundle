<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

require_once __DIR__ . '/../vendor/autoload.php';

$process = Process::fromShellCommandline('openssl version');
$process->mustRun();

echo $process->getOutput() . PHP_EOL;
