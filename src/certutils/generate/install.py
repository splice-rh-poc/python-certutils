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

import os
import shlex
import socket
import sys
import subprocess

from base import get_parser, run_command

def restart_httpd():
    cmd = "/sbin/service httpd restart"
    return run_command(cmd)

def copy_file(src, dst):
    cmd = "cp %s %s" % (src, dst)
    if not run_command(cmd):
        return False
    return True

def update_httpd_config(server_key, server_cert, ca_cert, httpd_ssl_config_file):
    server_key = server_key.replace("/", "\/")
    server_cert = server_cert.replace("/", "\/")
    ca_cert = ca_cert.replace("/", "\/")
    cmd = "sed -i 's/^SSLCertificateFile.*/SSLCertificateFile %s/' %s" % (server_cert, httpd_ssl_config_file)
    if not run_command(cmd):
        return False
    cmd = "sed -i 's/^SSLCertificateKeyFile.*/SSLCertificateKeyFile %s/' %s" % (server_key, httpd_ssl_config_file)
    if not run_command(cmd):
        return False
    cmd = "sed -i 's/^SSLCACertificateFile.*/SSLCACertificateFile %s/' %s" % (ca_cert, httpd_ssl_config_file)
    if not run_command(cmd):
        return False
    return True


def run(default_install_dir="/etc/pki/splice", httpd_ssl_config_file="/etc/httpd/conf.d/ssl.conf"):
    parser = get_parser(limit_options=["server_key", "server_cert", "ca_cert"])
    #parser.add_option("--install_dir", action="store",
    #        help="Install directory for server SSL cert/key.  Default is %s" % (default_install_dir),
    #        default=default_install_dir)
    (opts, args) = parser.parse_args()
    server_key = opts.server_key
    server_cert = opts.server_cert
    ca_cert = opts.ca_cert
    #install_dir = opts.install_dir

    #if not os.path.exists(install_dir):
    #    os.makedirs(install_dir)
    #installed_server_key = os.path.join(install_dir, os.path.basename(server_key))
    #installed_server_cert = os.path.join(install_dir, os.path.basename(server_cert))
    #installed_ca_cert = os.path.join(install_dir, os.path.basename(ca_cert))
    #if not copy_file(server_key, installed_server_key):
    #    print "Error installing server_key"
    #    sys.exit(1)
    #if not copy_file(server_cert, installed_server_cert):
    #    print "Error installing server_cert"
    #    sys.exit(1)
    #if not copy_file(ca_cert, installed_ca_cert):
    #    print "Error installing ca_cert"
    #    sys.exit(1)

    #if not update_httpd_config(installed_server_key, installed_server_cert, installed_ca_cert):
    if not update_httpd_config(server_key, server_cert, ca_cert, httpd_ssl_config_file):
        print "Error updating httpd"
        sys.exit(1)
    print "Httpd ssl.conf has been updated"

    if not restart_httpd():
        print "Error restarting httpd"
        sys.exit(1)
    return True


if __name__ == "__main__":
    run()