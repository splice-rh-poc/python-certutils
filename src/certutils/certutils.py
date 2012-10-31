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

from glob import glob

import datetime
import logging
import os
import shutil
import subprocess
import tempfile
import time

import M2Crypto
from M2Crypto import X509, BIO, RSA, EVP, util

LOG = logging.getLogger(__name__)

try:
    from M2Crypto.X509 import CRL_Stack
    M2CRYPTO_HAS_CRL_SUPPORT = True
except:
    M2CRYPTO_HAS_CRL_SUPPORT = False
    LOG.warning("**M2Crypto<%s> lacks patch for using Certificate Revocation Lists**" % (M2Crypto.version))

class CertificateParseException(Exception):
    def __init__(self, attempted_cert):
        super(CertificateParseException, self).__init__(self)
        self.attempted_cert = attempted_cert

    def __str__(self):
        return "Unable to parse certificate '%s'. Are you sure this is the ''contents'' " \
               "of the certificate and not just the filepath?" % (self.attempted_cert)

class CertUtils(object):

    def __init__(self, log_failed_cert=True, max_num_certs_in_chain=100, 
                 verbose=True, crl_location=''):
        self.log_failed_cert = log_failed_cert
        self.log_failed_cert_verbose = verbose
        self.max_num_certs_in_chain = max_num_certs_in_chain
        self.crl_location = crl_location

    def validate_priv_key_to_certificate(self, priv_key, cert_pem):
        """
        Validates if a given private key matches the given certificate
        @param priv_key: string private key data in PEM format
        @param cert_pem: string certificate data in PEM format
        @return: True if matches, False if not
        """
        cert = X509.load_cert_string(cert_pem)
        pub_key = cert.get_pubkey()
        pub_key.get_modulus()
        priv_key = EVP.load_key_string(priv_key)
        if pub_key.get_modulus() == priv_key.get_modulus():
            return True
        return False


    def validate_certificate(self, cert_pem, ca_pem, crl_pems=None, check_crls=True, crl_dir=None):
        '''
        Validates a certificate against a CA certificate and CRLs if they exist.
        Input expects PEM encoded strings.

        @param cert_pem: PEM encoded certificate
        @type  cert_pem: str

        @param ca_pem: PEM encoded CA certificates, allows chain of CA certificates if concatenated together
        @type  ca_pem: str

        @param crl_pems: List of CRLs, each CRL is a PEM encoded string
        @type  crl_pems: List[str]

        @param check_crls: Defaults to True, if False will skip CRL check
        @type  check_crls: boolean

        @param crl_dir: Path to search for CRLs, default is None which defaults to configuration file parameter
        @type  crl_dir: str

        @return: true if the certificate was signed by the given CA; false otherwise
        @rtype:  boolean
        '''
        cert = X509.load_cert_string(cert_pem)
        if not M2CRYPTO_HAS_CRL_SUPPORT:
            # Will only be able to use first CA from the ca_pem if it was a chain
            ca_cert = X509.load_cert_string(ca_pem)
            return cert.verify(ca_cert.get_pubkey())
        ca_chain = self.get_certs_from_string(ca_pem)
        crl_stack = X509.CRL_Stack()
        if check_crls:
            for ca in ca_chain:
                ca_hash = ca.get_issuer().as_hash()
                stack = self.get_crl_stack(ca_hash, crl_dir=crl_dir)
                for c in stack:
                    crl_stack.push(c)
            if crl_pems:
                for c in crl_pems:
                    crl_stack.push(X509.load_crl_string(c))
        return self.x509_verify_cert(cert, ca_chain, crl_stack)

    def x509_verify_cert(self, cert, ca_certs, crl_stack=None):
        """
        Validates a Certificate against a CA Certificate and a Stack of CRLs

        @param  cert:  Client certificate to verify
        @type   cert:  M2Crypto.X509.X509

        @param  ca_certs:  Chain of CA Certificates
        @type   ca_certs:  [M2Crypto.X509.X509]

        @param  crl_stack: Stack of CRLs, default is None
        @type   crl_stack: M2Crypto.X509.CRL_Stack

        @return: true if the certificate is verified by OpenSSL APIs, false otherwise
        @rtype:  boolean
        """
        store = X509.X509_Store()
        for ca in ca_certs:
            store.add_cert(ca)
        if crl_stack and len(crl_stack) > 0:
            store.set_flags(X509.m2.X509_V_FLAG_CRL_CHECK |
                       X509.m2.X509_V_FLAG_CRL_CHECK_ALL)
        store_ctx = X509.X509_Store_Context()
        store_ctx.init(store, cert)
        if crl_stack and len(crl_stack) > 0:
            store_ctx.add_crls(crl_stack)
        retval = store_ctx.verify_cert()
        if retval != 1:
            msg = "Cert verification failed against %s ca cert(s) and %s CRL(s)" % (len(ca_certs), len(crl_stack))
            if self.log_failed_cert:
                msg += "\n%s" % (self.get_debug_info_certs(cert, ca_certs, crl_stack))
            LOG.info(msg)
        return retval

    def get_crl_stack(self, issuer_hash, crl_dir=None):
        """
        @param issuer_hash: Hash value of the issuing certificate
        @type  issuer_hash: unsigned long

        @param crl_dir: Path to search for CRLs, default is None which defaults to configuration file parameter
        @type  crl_dir: str

        @return CRL_Stack of any CRLs issued by the issuer_hash
        @rtype: CRL_Stack: M2Crypto.X509.CRL_Stack
        """
        crl_stack = X509.CRL_Stack()
        if not crl_dir:
            crl_dir = self._crl_directory()
        if os.path.exists(crl_dir):
            search_path = "%s/%x.r*" % (crl_dir, issuer_hash)
            crl_paths = glob(search_path)
            for c in crl_paths:
                try:
                    crl = X509.load_crl(c)
                    crl_stack.push(crl)
                except:
                    LOG.exception("Unable to load CRL file: %s" % (c))
        return crl_stack

    def get_certs_from_string(self, data):
        """
        @param data: A single string of concatenated X509 Certificates in PEM format
        @type data: str

        @return list of X509 Certificates
        @rtype: [M2Crypto.X509.X509]
        """
        # Refer to OpenSSL crypto/x509/by_file.c
        # Function: X509_load_cert_file() to see how they parse a chain file and add
        # the certificates to a X509_Store.  Below follows a similar procedure.
        bio = BIO.MemoryBuffer(data)
        certs = []
        try:
            if not M2CRYPTO_HAS_CRL_SUPPORT:
                # Old versions of M2Crypto behave differently and would loop indefinitely over load_cert_bio
                return [X509.load_cert_string(data)]
            for index in range(0, self.max_num_certs_in_chain):
                # Read one cert at a time, 'bio' stores the last location read
                # Exception is raised when no more cert data is available
                cert = X509.load_cert_bio(bio)
                if not cert:
                    # This is likely to never occur, a X509Error should always be raised
                    break
                certs.append(cert)
                if index == (self.max_num_certs_in_chain - 1):
                    LOG.info("**WARNING** Pulp reached maximum number of <%s> certs supported in a chain." % (self.max_num_certs_in_chain))

        except X509.X509Error:
            # This is the normal return path.
            return certs
        return certs

    def get_subject_pieces(self, cert_str, lookup=None):
        """
        @param cert_str a x509 certificate as a string
        @type cert_str: str

        @param lookup, an optional list of strings to represent subject
                        identifiers to look up, example: ['CN', 'C', 'O', ..]
        @type lookup: [str]

        @return a dictionary of broken out items in the certs subject. example {"CN":"hostname",...}
        @rtype: {}
        """
        pieces = {}
        if not lookup:
            lookup = ["C", "CN", "Email", "GN", "L", "O", "OU", "SN"]
        x509_certs = self.get_certs_from_string(cert_str)
        # Grab the first cert if it exists
        if not x509_certs:
            raise CertificateParseException(cert_str)
        c = x509_certs[0]
        subject = c.get_subject()
        if not subject:
            return pieces
        for key in lookup:
            pieces[key] = getattr(subject, key)
        return pieces

    def get_debug_info_certs(self, cert, ca_certs, crl_stack):
        """
        Debug method to display information certificates.  Typically used to print info after a verification failed.
        @param cert: a X509 certificate
        @type cert: M2Crypto.X509.X509

        @param ca_certs: list of X509 CA certificates
        @type ca_certs: [M2Crypto.X509.X509]

        @param crl_stack: a stack of CRLs
        @type crl_stack: M2Crypto.X509.CRL_Stack

        @return: a debug message
        @rtype: str
        """
        msg = "Current Time: <%s>" % (time.asctime())
        if self.log_failed_cert_verbose:
            msg += "\n%s" % (cert.as_text())
        info = self.get_debug_X509(cert)
        msg += "\nCertificate to verify: \n\t%s" % (info)
        msg += "\nUsing a CA Chain with %s cert(s)" % (len(ca_certs))
        for ca in ca_certs:
            info = self.get_debug_X509(ca)
            msg += "\n\tCA: %s" % (info)
        msg += "\nUsing a CRL Stack with %s CRL(s)" % (len(crl_stack))
        for crl in crl_stack:
            info = self.get_debug_CRL(crl)
            msg += "\n\tCRL: %s" % (info)
        return msg

    def get_debug_X509(self, cert):
        """
        @param cert: a X509 certificate
        @type cert: M2Crypto.X509.X509

        @return: string of debug information about the passed in X509
        @rtype: str
        """
        msg = "subject=<%s>, issuer=<%s>, subject.as_hash=<%s>, issuer.as_hash=<%s>, fingerprint=<%s>, serial=<%s>, version=<%s>, check_ca=<%s>, notBefore=<%s>, notAfter=<%s>" % \
              (cert.get_subject(), cert.get_issuer(), cert.get_subject().as_hash(), cert.get_issuer().as_hash(), cert.get_fingerprint(), cert.get_serial_number(),
               cert.get_version(), cert.check_ca(), cert.get_not_before(), cert.get_not_after())
        return msg

    def get_debug_X509_Extensions(self, cert):
        """
        @param cert: a X509 certificate
        @type cert: M2Crypto.X509.X509

        @return: debug string
        @rtype: str
        """
        extensions = ""
        ext_count = cert.get_ext_count()
        for i in range(0, ext_count):
            ext = cert.get_ext_at(i)
            extensions += " %s:<%s>" % (ext.get_name(), ext.get_value())
        return extensions

    def get_debug_CRL(self, crl):
        """
        @param crl: a X509_CRL instance
        @type crl: M2Crypto.X509.CRL

        @return: string of debug information about the passed in CRL
        @rtype: str
        """
        msg = "issuer=<%s>, issuer.as_hash=<%s>" % (crl.get_issuer(), crl.get_issuer().as_hash())
        if hasattr(crl, "get_lastUpdate") and hasattr(crl, "get_nextUpdate"):
            nextUpdate = crl.get_nextUpdate()
            lastUpdate = crl.get_lastUpdate()
            msg += " lastUpdate=<%s>, nextUpdate=<%s>" % (lastUpdate, nextUpdate)
            try:
                now = datetime.datetime.now().date()
                next = nextUpdate.get_datetime().date()
                last = lastUpdate.get_datetime().date()
                if now > next:
                    msg += "\n** ** WARNING ** **: Looks like this CRL is expired.  nextUpdate = <%s>" % (nextUpdate)
                if now < last:
                    msg += "\n** ** WARNING ** **: Looks like this CRL is premature. lastUpdate = <%s>" % (lastUpdate)
            except:
                pass
        return msg

    def _crl_directory(self):
        '''
        Returns the absolute path to the directory in which
        Certificate Revocation Lists (CRLs) are stored

        @return: absolute path to a directory that may not exist
        @rtype:  str
        '''
        return self.crl_location


    def generate(self, ca_cert_filename, ca_key_filename, days, name_attributes):
        '''
        Generates an X509 certificate

        @param cert_name: logical name of the certificate, used in the cert and key names
        @type  cert_name: str

        @param dest_dir: full path to the directory in which to store the generated cert;
                         will be created if it does not exist
        @type  dest_dir: str

        @param ca_cert_filename: full path to the CA certificate used to sign the generated cert
        @type  ca_cert_filename: str

        @param ca_key_filename: full path to the CA private key
        @type  ca_key_filename: str

        @param days: number of days the certificate should be valid for
        @type  days: int
        '''

        # Temporary working directory
        dest_dir = tempfile.mkdtemp()

        cert_name = 'rhic'

        try:
            self._generate_cert_request(dest_dir, cert_name, name_attributes)
            exit_code = self._sign_request(dest_dir, cert_name, ca_cert_filename, ca_key_filename, days)
            public_cert = open(self._cert_filename(dest_dir, cert_name)).read()
            private_key = open(self._priv_key_filename(dest_dir, cert_name)).read()
        finally:
            shutil.rmtree(dest_dir)

        return public_cert, private_key

    def _generate_cert_request(self, dest_dir, cert_name, name_attributes):

        priv_key_filename = self._priv_key_filename(dest_dir, cert_name)
        cert_filename = self._cert_filename(dest_dir, cert_name)
        csr_filename = self._csr_filename(dest_dir, cert_name)

        # Generate private key
        rsa = RSA.gen_key(2048, 65537)
        pk = EVP.PKey()
        pk.assign_rsa(rsa)

        pk.save_key(priv_key_filename, cipher=None, callback=util.no_passphrase_callback)

        # This is... ugh, man, this is ugly. Big surprise, M2Crypto doesn't expose a way
        # to convert PKCS8 to RSA format, so shell out to openssl to do it
        cmd = 'openssl rsa -in %s -out %s' % (priv_key_filename, priv_key_filename)
        
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()
        exit_code = p.returncode
        output = p.stdout.read()
        error = p.stderr.read()

        LOG.info('Private key creation output')
        LOG.info('Exit Code: ' + str(exit_code))
        LOG.info(output)
        LOG.info(error)

        # Generate request
        request = X509.Request()
        request.set_pubkey(pk)
        request.set_version(3)

        name = request.get_subject()
        for name_attr, value in name_attributes.items():
            setattr(name, name_attr, value)

        request.sign(pk, 'sha1')

        # The RHEL 5 version of m2crypto (0.16) doesn't have the save method defined, so manually
        # write out the PEM
        # request.save(csr_file)

        f = open(csr_filename, 'w')
        f.write(request.as_pem())
        f.close()

    def _sign_request(self, dest_dir, cert_name, ca_cert_filename, ca_key_filename, days=365):
        '''
        Signs the certificate request generated by _generate_cert_request.

        M2Crypto doesn't seem to have a way of signing a CSR with a CA certificate;
        it only looks like it supports self-signed certificates. As such, the quickest
        solution was to use a system call out to openssl directly.


        @return: exit code of the openssl process to sign the certificate request
        @rtype:  int
        '''
        csr_filename = self._csr_filename(dest_dir, cert_name)
        crt_filename = self._cert_filename(dest_dir, cert_name)
        ca_srl_filename = os.path.join(os.path.dirname(ca_cert_filename), 
            '%s.srl' % (os.path.basename(os.path.splitext(ca_cert_filename)[0])))

        cmd = 'openssl x509 -req -days %s -in %s -CA %s -CAkey %s -CAserial %s -out %s' % \
              (days, csr_filename, ca_cert_filename, ca_key_filename,
               ca_srl_filename, crt_filename)

        LOG.info('Command [%s]' % cmd)

        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()
        exit_code = p.returncode
        output = p.stdout.read()
        error = p.stderr.read()

        LOG.info('Certificate creation output')
        LOG.info(output)
        LOG.info(error)

        return exit_code

    def _priv_key_filename(self, dest_dir, cert_name):
        return os.path.join(dest_dir, '%s.key' % cert_name)

    def _csr_filename(self, dest_dir, cert_name):
        return os.path.join(dest_dir, '%s.csr' % cert_name)

    def _cert_filename(self, dest_dir, cert_name):
        return os.path.join(dest_dir, '%s.crt' % cert_name)

class CertFileUtils(CertUtils):

    def read_pem(self, pem_path):
        # Exceptions bubble up
        return open(pem_path).read()

    def validate_certificate(self, cert_filename, ca_filename):
        cert_pem = self.read_pem(cert_filename)
        ca_pem = self.read_pem(ca_filename)
        return super(CertFileUtils, self).validate_certificate(cert_pem, ca_pem)

    def validate_priv_key_to_certificate(self, key_filename, cert_filename):
        key_pem = self.read_pem(key_filename)
        cert_pem = self.read_pem(cert_filename)
        return super(CertFileUtils, self).validate_priv_key_to_certificate(key_pem, cert_pem)