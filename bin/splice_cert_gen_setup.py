#!/usr/bin/env python

from certutils.generate import create_ca, create_server_cert, install

if __name__ == "__main__":
    create_ca.run()
    create_server_cert.run()
    install.run(httpd_ssl_config_file="/etc/httpd/conf.d/splice.conf")

    
