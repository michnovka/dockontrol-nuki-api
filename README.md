# DOCKontrol NUKI API

Bridge between https://github.com/michnovka/dockontrol and LAN NUKI bridge to allow locking and unlocking

## Requirements

PHP 7.4+ (with SQLite3 and BCMath), synchronized time with NTP

## Configuration

Rename `libs/config.php.template` to `libs/config.php` and adjust settings. Local NUKI bridge must be configured to accept [HTTP Bridge API requests](https://developer.nuki.io/page/nuki-bridge-http-api-1-11/4/).