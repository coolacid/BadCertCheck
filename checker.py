import M2Crypto, os, pprint
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

def CheckHost(address, roots):
    context = M2Crypto.SSL.Context();
#    context.set_allow_unknown_ca(True)
#    context.set_verify(M2Crypto.SSL.verify_none, True)

    conn = M2Crypto.SSL.Connection(context)
    try:
        conn.connect((address, 443))
    except WrongHost as e:
        print "WARNING: %s\n" % e

    cert_chain = conn.get_peer_cert_chain()
    badcert = False

    print "Certificate Chain Presented by Server:"
    for cert in cert_chain:
        if cert.get_fingerprint("sha256").lower() in roots['fingerprints']:
            badcert = True
        try:
            ki = cert.get_ext("subjectKeyIdentifier").get_value().replace(":", "").lower()
            if ki in roots['identifier']:
                print "Found Bad KI"
                badcert = True
        except LookupError:
            ki = ""
        print "Subject: %s\nFingerprint: %s\nSerial: %02x\nSubject Key Identifier: %s\n" % (cert.get_subject().as_text(), cert.get_fingerprint("sha256"), cert.get_serial_number(), ki)

    if badcert:
        print "\n*** KNOWN BAD CERT IN THE CHAIN ***"
    else:
        print "\nAll Clear"


def LoadRoots():
    certfp = []
    certki = []
    for filename in os.listdir('roots'):
        if filename.endswith("pem"):
            cert = M2Crypto.X509.load_cert("roots/%s" % filename)
            certfp.append(cert.get_fingerprint("sha256").lower())
            try:
                certki.append(cert.get_ext("subjectKeyIdentifier").get_value().replace(":", "").lower())
            except LookupError:
                pass

    return {"fingerprints": certfp, "identifier": certki}


rootcas = LoadRoots()
# pprint.pprint(rootcas)
CheckHost(address, rootcas)

