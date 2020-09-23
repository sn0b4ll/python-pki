# python-pki
## How-To-Use
First and only one time run:

`python3 -m pip install -r requirements.txt`

and copy the `template/config.conf_dummy` to `./config.conf`. Adjust the values as needed.

Afterwards you can start the tool with:

`python3 python-pki.py`

## Description
This is an small python-tool for managing an CA with Client-Certificates for small environments.

## Functions
The interactive console provides the following functions:

Name | Description
--- | ---
help | Shows all available commands
addca | Adds an new CA
addcert | Adds an new Certificate, signed by an CA
getcas | Shows all stored CAs
getcerts | Shows all stored Certs
getcertsforca | Show all Cert for an CA
exportca | Exports an CA
exportcert | Exports an Cert
exit | Escape this hell

## Security
This tool provides a certain degree of security for the private keys of the CA and the Certs. The private key is encrypted in storage using Fernet (https://cryptography.io/en/latest/fernet/) with an key which is generated when an DB is first created (and can't be changed). All other fields are not encrypted - I prefer KISS and encryption is not always Simple and Stupid, so currently only the private keys are encrypted. If you think all field should be encrypted, please file an issue or make a pull-request :)

## TODOs
This tool is usable, but far from finished. For all TODOs, please check the issues on https://github.com/sn0b4ll/python-pki/issues
