<?php
// Synthetic navigation fixture; do not run or deploy.
function readDocument($base) {
    $name = $_GET['name'];
    return file_get_contents($base . $name);
}
