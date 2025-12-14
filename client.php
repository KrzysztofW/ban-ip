<?php
$fp = stream_socket_client("tcp://localhost:7777", $errno, $errstr, 3);
if (!$fp) {
    /* echo "$errstr ($errno)<br />\n"; */
    return;
}
/* $ip = "2.2.2.255"; */

/* direct usage */
/* $ip = $_SERVER['REMOTE_ADDR']; */

$ip = $_SERVER['REMOTE_ADDR'];
/* if used behide a reverse proxy */
#$x_for = $_SERVER['HTTP_X_FORWARDED_FOR'];
#$l = explode(",", $x_for);
#$ip = trim(end($l));

/* see common.h for padding lengths */
$cmd = "ban";
$desc = "application name";

$to_send = $cmd."\x00".$ip."\x00".$desc;
$len = pack("n", strlen($to_send)); // 'n' = 16-bit unsigned, big-endian
$to_send = $len.$to_send;

fwrite($fp, $to_send);
fclose($fp);
?>
