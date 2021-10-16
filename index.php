<?php

namespace Dockontrol\NukiAPI;

use SQLite3;

require_once dirname(__FILE__).'/libs/config.php';
/** @var string $SQLITE_FILE */
/** @var array $access_list */

require_once dirname(__FILE__).'/libs/lib_totp.php';

function APIError($message){
    echo json_encode([
        'status' => 'error',
        'message' => $message
    ]);
    exit;
}

$access = null;

if(!empty($access_list[$_GET['username']])){
	$access = $access_list[$_GET['username']];
}else{
	APIError("Unauthorized");
}

/** @var Access $access */

if(!$access->CheckIPAndDomainWhitelist($_SERVER['REMOTE_ADDR'])){
	APIError("Unauthorized");
}

$nonce = substr($_GET['nonce'], 0, 32);
$totps = intval($_GET['totp1']).'|'.intval($_GET['totp2']);

$db = new SQLite3($SQLITE_FILE);

$db->exec('CREATE TABLE IF NOT EXISTS nonces(totps TEXT PRIMARY KEY, nonce TEXT, created_time INT);');
$db->exec('DELETE FROM nonces WHERE created_time < '.(time()-3600));
$nonce_used = $db->querySingle('SELECT 1 FROM nonces WHERE totps="'.SQLite3::escapeString($totps).'" AND nonce = "'.SQLite3::escapeString($nonce).'" LIMIT 1;') ? true : false;

if($nonce_used){
	APIError("Nonce used");
}

$db->query('INSERT INTO nonces(totps, nonce, created_time) VALUES ("'.SQLite3::escapeString($totps).'","'.SQLite3::escapeString($nonce).'",'.time().');');

if(!$access->CheckTOTPs($nonce, $_GET['totp1'], $_GET['totp2'])){
	APIError("Unauthorized");
}

$nuki_ip = $access->getNukiIP();
$nuki_id = $access->getNukiID();
$nuki_port = $access->getNukiPort();
$nuki_token = $access->getNukiToken();
$device_type = $access->getDeviceType();

$nuki_action = null;

$is_sandbox = $access->isSandbox();

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

$reply = array();

if($is_sandbox){
	$reply['success'] = true;
}else {
	$url = 'http://' . $nuki_ip . ':' . $nuki_port . '/lockAction?nukiId=' . intval($nuki_id) . '&deviceType=' . $device_type . '&action=' . intval($nuki_action) . '&nowait=1&ts=' . $ts . '&rnr=' . $rnr . '&hash=' . $hash;
	
	$ch = curl_init();
	$headers = array(
		'Accept: application/json',
		'Content-Type: application/json',
	);
	
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	$reply_raw = curl_exec($ch);
	$reply = json_decode($reply_raw, true);
}

if($reply['success']){
	echo json_encode(array(
		'status' => 'ok',
		'message' => 'Unlocked'
	));
	exit;
}else{
	APIError("Unknown error on local API");
}