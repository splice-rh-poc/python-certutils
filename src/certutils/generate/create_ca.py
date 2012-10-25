#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2012 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

# Reference: Blog post from Jason Dobies
# http://blog.pulpproject.org/2011/05/18/pulp-protected-repositories/

import os
import shlex
import socket
import sys
import subprocess

from base import get_parser, run_command, check_dirs

def create_ca_key(ca_key_name):
    check_dirs(ca_key_name)
    cmd = "openssl genrsa -out %s 2048" % (ca_key_name)
    return run_command(cmd)

def create_ca_cert(ca_key_name, ca_cert_name):
    check_dirs(ca_key_name)
    cmd = ("openssl req -new -x509 -days 10950 -key %s -out %s -subj '/C=US/ST=NC/L=Raleigh/O=Red Hat/OU=Splice/CN=Splice-Root-CA'") % (ca_key_name, ca_cert_name)
    return run_command(cmd)

def create_serial(ca_serial):
    if not os.path.exists(os.path.dirname(ca_serial)):
        os.makedirs(os.path.dirname(ca_serial))
    f = open(ca_serial, "w")
    try:
        f.write("01")
    finally:
        f.close()
    return True

def run():
    parser = get_parser(limit_options=["ca_key", "ca_cert", "ca_serial"])
    (opts, args) = parser.parse_args()

    ca_key = opts.ca_key
    ca_cert = opts.ca_cert
    ca_serial = opts.ca_serial

    if not create_ca_key(ca_key):
        print "Failed to create CA key"
        sys.exit(1)

    if not create_ca_cert(ca_key, ca_cert):
        print "Failed to create CA cert"
        sys.exit(1)

    if not create_serial(ca_serial):
        print "Failed to create CA serial file: %s" % (ca_serial)
        sys.exit(1)

    print "CA Key: %s" % (ca_key)
    print "CA Cert: %s" % (ca_cert)
    return True

if __name__ == "__main__":
    run()