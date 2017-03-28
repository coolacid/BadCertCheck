# BadCertCheck
Check for possible EV Cert Problems

Google has announced their intention to de-trust certs from Symantec CAs [See Here](https://groups.google.com/a/chromium.org/forum/m/#!msg/blink-dev/eUAKwjihhBs/rpxMXjZHCQAJ)

This tool is a simple check to pull the CA chain from a domain and check to see if any of the certs are listed to be de-trusted. 

You can find the list of certs to be de-trusted [here](https://chromium.googlesource.com/chromium/src/+/master/net/data/ssl/symantec/roots/)

USAGE:

`python checker.py [HOSTNAME]`

NOTE: Use the hostname, not URL

