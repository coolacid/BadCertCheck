import M2Crypto
import roots
from optparse import OptionParser
from M2Crypto.SSL.Checker import WrongHost

usage = "Usage: %prog HOSTNAME"
parser = OptionParser(usage)

# Basis for this from https://gist.github.com/zakird/1346293

(options, args) = parser.parse_args()

if len(args) != 1:
    print "HOSTNAME not supplied, using google"
    address = "www.google.com"
else:
    address = args[0]


context = M2Crypto.SSL.Context();
context.set_allow_unknown_ca(True)
context.set_verify(M2Crypto.SSL.verify_none, True)

conn = M2Crypto.SSL.Connection(context)
try:
    conn.connect((address, 443))
except WrongHost as e:
    print "ERROR:\n%s\n" % e

cert_chain = conn.get_peer_cert_chain()
badcert = False

for cert in cert_chain:
    print "%s: %s" % (cert.get_subject().as_text(), cert.get_fingerprint("sha256"))
    if cert.get_fingerprint("sha256").lower() in roots.roots:
        badcert = True

if badcert:
    print "\n\nKNOWN BAD CERT IN THE CHAIN"
else:
    print "\n\nAll Clear"


