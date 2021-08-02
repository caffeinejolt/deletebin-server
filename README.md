# DeleteBin Server

This is the small server-side component of [DeleteBin.org](https://deletebin.org) written in Go.  It is used to service API requests.  The goals of this project include:

 - Keep things secure
 - Keep things simple
 - Be transparent
 - Get valuable contributions to improve

## Database

[BadgerDB](https://github.com/dgraph-io/badger) is used to store all values.  Any key-value database could be used, but BadgerDB does offer some nice built-in features (i.e. values can have a TTL associated with them) along with good performance.

## Recommended Environment

We run this server process in an isolated read-only container (only the database mount is writable), as a limited user/group, with all Linux capabilities removed, in its own SELinux context.  In other words, it is recommended to limit the server process to absolutely only what it needs... and nothing else.  Additionally, we run this process behind a dedicated web server process which handles issues such as rate limits, capping request size, etc.

## Usage

All server config values are stored in a JSON config file.  The only command switch specifies the path to the config file: -config

## Example config

Here is an example config file:

    {
	    "DBPath": "/path/to/database",
	    "Debug": true,
	    "Listen": ":12345",
	    "HCSiteKey": "abc123",
	    "HCSecret": "abc123",
	    "AbuseMail": "abuse@example.com",
	    "Mail": "abuse@example.com",
	    "RealIPHeader": "X-Real-IP",
	    "RTLRRMinRange": 100,
	    "RTLRRMinRatio": 0.05,
	    "RTLRR": {}
    }


## Other Repos

In case you are looking for something other than the server component, here are the other DeleteBin related repos:

 - DeleteBin Browser Extension
