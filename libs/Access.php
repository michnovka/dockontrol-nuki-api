<?php

namespace Dockontrol\NukiAPI;

use GoogleAuthenticator;

require_once dirname(__FILE__).'/lib_totp.php';

class Access
{
	private string $password1;
	private string $password2;
	private string $nuki_ip;
	private int $nuki_port;
	private int $nuki_id;
	private string $nuki_token;
	private string $device_type;
	private array $ip_whitelist;
	private array $domain_whitelist;
	private bool $sandbox = false;
	/**
	 * @return string
	 */
	public function getPassword1(): string
	{
		return $this->password1;
	}
	
	/**
	 * @param string $password1
	 */
	public function setPassword1(string $password1): void
	{
		$this->password1 = $password1;
	}
	
	/**
	 * @return string
	 */
	public function getPassword2(): string
	{
		return $this->password2;
	}
	
	/**
	 * @param string $password2
	 */
	public function setPassword2(string $password2): void
	{
		$this->password2 = $password2;
	}
	
	/**
	 * @return string
	 */
	public function getNukiIP(): string
	{
		return $this->nuki_ip;
	}
	
	/**
	 * @param string $nuki_ip
	 */
	public function setNukiIP(string $nuki_ip): void
	{
		$this->nuki_ip = $nuki_ip;
	}
	
	/**
	 * @return int
	 */
	public function getNukiPort(): int
	{
		return $this->nuki_port;
	}
	
	/**
	 * @param int $nuki_port
	 */
	public function setNukiPort(int $nuki_port): void
	{
		$this->nuki_port = $nuki_port;
	}
	
	/**
	 * @return int
	 */
	public function getNukiID(): int
	{
		return $this->nuki_id;
	}
	
	/**
	 * @param int $nuki_id
	 */
	public function setNukiID(int $nuki_id): void
	{
		$this->nuki_id = $nuki_id;
	}
	
	/**
	 * @return string
	 */
	public function getNukiToken(): string
	{
		return $this->nuki_token;
	}
	
	/**
	 * @param string $nuki_token
	 */
	public function setNukiToken(string $nuki_token): void
	{
		$this->nuki_token = $nuki_token;
	}
	
	/**
	 * @return string
	 */
	public function getDeviceType(): string
	{
		return $this->device_type;
	}
	
	/**
	 * @param string $device_type
	 */
	public function setDeviceType(string $device_type): void
	{
		$this->device_type = $device_type;
	}
	
	/**
	 * @return array
	 */
	public function getIpWhitelist(): array
	{
		return $this->ip_whitelist;
	}
	
	/**
	 * @param array $ip_whitelist
	 */
	public function setIpWhitelist(array $ip_whitelist): void
	{
		$this->ip_whitelist = $ip_whitelist;
	}
	
	/**
	 * @return array
	 */
	public function getDomainWhitelist(): array
	{
		return $this->domain_whitelist;
	}
	
	/**
	 * @param array $domain_whitelist
	 */
	public function setDomainWhitelist(array $domain_whitelist): void
	{
		$this->domain_whitelist = $domain_whitelist;
	}
	
	public function isSandbox(): bool
	{
		return $this->sandbox;
	}
	
	public function setSandbox(bool $sandbox): void
	{
		$this->sandbox = $sandbox;
	}
	
	
	public function __construct(string $password1, string $password2, string $nuki_ip, int $nuki_port, int $nuki_id, string $nuki_token, string $device_type = '0', array $ip_whitelist = [], array $domain_whitelist = [], $sandbox = false)
	{
		$this->password1 = $password1;
		$this->password2 = $password2;
		$this->nuki_ip = $nuki_ip;
		$this->nuki_port = $nuki_port;
		$this->nuki_id = $nuki_id;
		$this->nuki_token = $nuki_token;
		$this->device_type = $device_type;
		$this->ip_whitelist = $ip_whitelist;
		$this->domain_whitelist = $domain_whitelist;
		$this->sandbox = $sandbox;
	}
	
	public function CheckIPAndDomainWhitelist($ip): bool
	{
		$access_granted = true;
		
		if(!empty($this->getIpWhitelist()) && !in_array($ip, $this->getIpWhitelist())){
			$access_granted = false;

            if(!empty($this->getDomainWhitelist())){
				foreach($this->getDomainWhitelist() as $domain){
					$ips = gethostbynamel($domain);

					if(in_array($ip, $ips)){
						$access_granted = true;
						break;
					}
				}
			}
			
		}
		
		return $access_granted;
	}
	
	public function CheckTOTPs($nonce, $totp1, $totp2): bool
	{

		// authenticate TOTP1 and TOTP2
		$secret1 = str_pad(GoogleAuthenticator::hex_to_base32(substr(hash('sha256', $this->getPassword1()),0,20)), 16, 'A', STR_PAD_LEFT).str_pad(GoogleAuthenticator::hex_to_base32(substr(hash('sha256', $nonce),0,10)), 8, 'A', STR_PAD_LEFT);
		$secret2 = str_pad(GoogleAuthenticator::hex_to_base32(substr(hash('sha256', $this->getPassword2()),0,20)), 16, 'A', STR_PAD_LEFT).str_pad(GoogleAuthenticator::hex_to_base32(substr(hash('sha256', $nonce),0,10)), 8, 'A', STR_PAD_LEFT);
		
		if(
			empty($totp1) || strlen($totp1) != 6 ||
			empty($totp2) || strlen($totp2) != 6 ||
			!GoogleAuthenticator::check_totp($secret1, $totp1)
			|| !GoogleAuthenticator::check_totp($secret2, $totp2)
		){
			return false;
		}
		
		return true;
	}
	
}