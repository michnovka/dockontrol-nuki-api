<?php

require_once dirname(__FILE__).'/libs/config.php';
require_once dirname(__FILE__).'/libs/lib_totp.php';

function APIError($message){
    echo json_encode(array(
        'status' => 'error',
        'message' => $message
    ));
    exit;
}

if(empty($access[$_GET['username']])){
	APIError("Unauthorized");
}
if(!empty($access[$_GET['username']]['ip_whitelist']) && !in_array($_SERVER['REMOTE_ADDR'], $access[$_GET['username']]['ip_whitelist'])){
	APIError("Unauthorized IP");
}

$password1 = $access[$_GET['username']]['password1'];
$password2 = $access[$_GET['username']]['password2'];

// authenticate TOTP1 and TOTP2
$secret1 = GoogleAuthenticator::hex_to_base32(substr(hash('sha256', $password1),0,20));
$secret2 = GoogleAuthenticator::hex_to_base32(substr(hash('sha256', $password2),0,20));

if(
	empty($_GET['totp1']) || strlen($_GET['totp1']) != 6 ||
	empty($_GET['totp2']) || strlen($_GET['totp2']) != 6 ||
	!GoogleAuthenticator::check_totp($secret1, $_GET['totp1'])
	|| !GoogleAuthenticator::check_totp($secret2, $_GET['totp2'])
){
	APIError("Unauthorized");
}

$nuki_ip = $access[$_GET['username']]['nuki_ip'];
$nuki_id = $access[$_GET['username']]['nuki_id'];
$nuki_port = $access[$_GET['username']]['nuki_port'];
$nuki_token = $access[$_GET['username']]['nuki_token'];
$device_type = $access[$_GET['username']]['device_type'];

$nuki_action = null;

switch($_GET['action']) {
	case 'unlock':
		// unlatch
		$nuki_action = '3';
		break;
	case 'lock':
		// lock
		$nuki_action = '2';
		break;
	default:
		APIError("Unauthorized");
}

$ts = gmdate('Y-m-d')."T".gmdate('H:i:s')."Z";
$rnr = rand(0, 65535);
$hash = hash('sha256', $ts.','.$rnr.",".$nuki_token);

$url = 'http://'.$nuki_ip.':'.$nuki_port.'/lockAction?nukiId='.intval($nuki_id).'&deviceType='.$device_type.'&action='.intval($nuki_action).'&nowait=0&ts='.$ts.'&rnr='.$rnr.'&hash='.$hash;

$ch = curl_init();
$headers = array(
	'Accept: application/json',
	'Content-Type: application/json',
);

curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$reply = json_decode(curl_exec($ch), true);

if($reply['success']){
	echo json_encode(array(
		'status' => 'ok',
		'message' => 'Unlocked'
	));
	exit;
}else{
	APIError("Unknown error");
}