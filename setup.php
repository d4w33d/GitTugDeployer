<?php

$distRepositoryUrl = 'https://github.com/d4w33d/GitTugDeployer/archive/refs/heads/main.zip';

stream_wrapper_register('gtds', 'GitTugDeployerStream');
$zipRaw = file_get_contents($distRepositoryUrl);
file_put_contents($streamPath = 'gtds://repository', $zipRaw);

$zip = new ZipArchive();
if ($zip->open($streamPath) !== true) die("Error uncompressing ${distRepositoryUrl}.\n");
$zip->extractTo('/www/lcfweb/test123');
$zip->close();
echo "Done.\n";
