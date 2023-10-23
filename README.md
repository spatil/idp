## Generate the cert and key

openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout dp.key -out dp.crt
