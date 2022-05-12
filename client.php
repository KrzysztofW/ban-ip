<?php
$fp = stream_socket_client("tcp://localhost:7777", $errno, $errstr, 3);
if (!$fp) {
    /* echo "$errstr ($errno)<br />\n"; */
    return;
}
/* $ip = "2.2.2.255"; */
$ip = $_SERVER['REMOTE_ADDR'];

/* see common.h for padding lengths */
$ip = str_pad($ip,  16, "\x00");
$cmd = str_pad("ban", 10, "\x00");

fwrite($fp, $ip.$cmd);
fclose($fp);
?>
