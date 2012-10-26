#!/usr/bin/env python
import random
import socket
import sys
from optparse import OptionParser

from certutils.generate.base import run_command
from certutils.generate.create_server_cert import create_server_key, create_server_csr

def get_serial_number():
    return random.randint(0, sys.maxint)

def create_server_cert(server_cert, server_csr, ca_cert, ca_key):
    cmd = "openssl x509 -req -days 10950 -CA %s -CAkey %s -in %s -out %s -set_serial %s" \
            % (ca_cert, ca_key, server_csr, server_cert, get_serial_number())
    return run_command(cmd)


if __name__ == "__main__":
    default_id = socket.gethostname()
    parser = OptionParser(description="Generate an identity certificate")
    parser.add_option("--cacert", action="store", help="CA Certificate", default="/etc/pki/splice/Splice_testing_root_CA.crt")
    parser.add_option("--cakey", action="store", help="CA Private Key", default="/etc/pki/splice/Splice_testing_root_CA.key")
    parser.add_option("--caserial", action="store", help="CA Serial database", default=None)
    parser.add_option("--outkey", action="store", help="Output file path for desired private key", 
            default="/tmp/Splice_identity.key")
    parser.add_option("--outcert", action="store", help="Output file path for desired public certificate", 
            default="/tmp/Splice_identity.cert")
    parser.add_option("--outcsr", action="store", help="Output file path for certificate signing request", 
            default="/tmp/Splice_identity.csr")
    parser.add_option("--id", action="store", 
            help="Identifier to embed in certificate's subject, default is CN=%s" % (default_id), 
            default=default_id)

    (opts, args) = parser.parse_args()

    cacert = opts.cacert
    cakey = opts.cakey
    server_key = opts.outkey
    server_cert = opts.outcert
    cert_id = opts.id
    csr = opts.outcsr
    status, stdout, stderr = create_server_key(server_key)
    status, stdout, stderr = create_server_csr(server_key, csr, cert_id)
    status, stdout, stderr = create_server_cert(server_cert, csr, cacert, cakey)
