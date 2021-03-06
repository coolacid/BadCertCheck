#!/usr/bin/env python

import M2Crypto, os, pprint
from optparse import OptionParser
from M2Crypto.SSL.Checker import WrongHost

# Basis for this from https://gist.github.com/zakird/1346293

# Keep a list of Excluded SHA256s
excluded = [ 
        "c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36",
        "17f96609ac6ad0a2d6ab0a21b2d1b5b2946bd04dbf120703d1def6fb62f4b661",
        "3db76d1dd7d3a759dccc3f8fa7f68675c080cb095e4881063a6b850fdd68b8bc",
        "6115f06a338a649e61585210e76f2ece3989bca65a62b066040cd7c5f408edd0",
        "904fb5a437754b1b32b80ebae7416db63d05f56a9939720b7c8e3dcc54f6a3d1",
        "ac2b922ecfd5e01711772fea8ed372de9d1e2245fce3f57a9cdbec77296a424b",
        "d6e4e7b9af3bd5a8f2d6321cde26639c25644f7307ce16aad347d9ad53d3ce13"
        ]

# Main function that checks an address
def CheckHost(address, roots):
    context = M2Crypto.SSL.Context();
#    context.set_allow_unknown_ca(True)
#    context.set_verify(M2Crypto.SSL.verify_none, True)

    conn = M2Crypto.SSL.Connection(context)
    conn.set_tlsext_host_name(address)
    try:
        conn.connect((address, 443))
    except WrongHost as e:
        print "WARNING: %s\n" % e

    cert_chain = conn.get_peer_cert_chain()
    result = {'exclude': False, 'badcert': False, "badki": False, "certs": [] }

    # Iterate over each cert in the presented cert chain
    for cert in cert_chain:
        exclude = badcert = badki = False
        # If the certs SHA256 is in the excluded list, we can just assume we're going to be fine
        if cert.get_fingerprint("sha256").lower() in excluded:
            result['exclude'] = True
            exclude = True

        # If the certs SHA256 is in the list of Bad figureprints, we know it's a bad cert in the chain
        if cert.get_fingerprint("sha256").lower() in roots['fingerprints']:
            result['badcert'] = True
            badcert = True

        # For each cert, check it's Authority Key Identifier, if that ID is in the bad Subject Identifier List, then this cert is signed by a bad cert. 
        # Keep in mind, the cert present in the certificate chain MAY NOT BE the correct cert expected by browsers, so, we check this here
        try:
            ki = cert.get_ext("authorityKeyIdentifier").get_value().replace(":", "").lower().strip().replace("keyid", "")
            if ki in roots['identifier']:
                result['badki'] = True
                badki = True
        except LookupError:
            ki = ""

        result['certs'].append({'subject': cert.get_subject().as_text(), 'fingerprint': cert.get_fingerprint("sha256"), 'serialnumber': cert.get_serial_number(), "ki": ki, "exclude": exclude, 'badcert': badcert, 'badki': badki })

    return result

def LoadRoots():
    certfp = []
    certki = []
    # Iterate over all the certs in roots and compile a list of SHA256s and Subject Key Identifiers
    for filename in os.listdir('roots'):
        if filename.endswith("pem"):
            cert = M2Crypto.X509.load_cert("roots/%s" % filename)
            certfp.append(cert.get_fingerprint("sha256").lower())
            try:
                certki.append(cert.get_ext("subjectKeyIdentifier").get_value().replace(":", "").lower())
            except LookupError:
                pass

    return {"fingerprints": certfp, "identifier": certki}

if __name__ == "__main__":
    usage = "Usage: %prog HOSTNAME"
    parser = OptionParser(usage)

    (options, args) = parser.parse_args()

    if len(args) != 1:
        print "WARNING: HOSTNAME not supplied, using www.google.com\n\n"
        address = "www.google.com"
    else:
        address = args[0]

    rootcas = LoadRoots()
#    pprint.pprint(rootcas)
    result = CheckHost(address, rootcas)

    print "Certificate Chain Presented by Server:"
    for cert in result['certs']:
        if cert['exclude']:
            print "Found an excluded cert"
        if cert['badcert']:
            print "Found a bad cert"
        if cert['badki']:
            print "Found a bad Authority Key Identifier"
        print "Subject: %s\nFingerprint: %s\nSerial: %02x\nAuthority Key Identifier: %s\n" % (cert['subject'], cert['fingerprint'], cert['serialnumber'], cert['ki'])

    if (result['badcert'] or result['badki']) and not result['exclude']:
        print "\n*** KNOWN BAD CERT IN THE CHAIN ***"
        exit(2)
    else:
        print "\nAll Clear"
        exit(0)
