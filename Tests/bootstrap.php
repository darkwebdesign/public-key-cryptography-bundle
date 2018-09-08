<?php

use Symfony\Component\Process\Process;

require_once __DIR__ . '/../vendor/autoload.php';

$process = new Process('openssl version');
$process->mustRun();

echo $process->getOutput() . PHP_EOL;
