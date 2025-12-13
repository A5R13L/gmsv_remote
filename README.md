# gmsv_remote

A Garry's Mod module that allows you to edit your files straight from vscode without needing SSH or SFTP.

# Usage

Simply place `require("remote")` anywhere in file located in `/garrysmod/lua/autorun/server/` (example: `/garrysmod/lua/autorun/server/gmsv_remote.lua`).

# Information

On first startup, the module with create `gmsv_remote/config.json` file in the root of your server. This will come pre-generated with a random password and the default relay url.
In this config file, you can edit the password, encryption key, and relay url to your liking.
The default relay is hosted on a cloudflare worker at [gmsv_remote_relay](https://github.com/A5R13L/gmsv_remote_relay) which should have near-zero downtime.

In order to connect and utilize this, you must use the [gmsv_remote_extension](https://github.com/A5R13L/gmsv_remote_extension) vscode extension.

When adding a new server in the extension, ensure the server address is the public facing one i.e: `185.169.43.55:27015` as well as having the same exact password and encryption key.