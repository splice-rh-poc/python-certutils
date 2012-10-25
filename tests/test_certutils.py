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


from unittest import TestCase

import logging
import os
import sys

sys.path.insert(0, '../src')
from certutils.certutils import CertUtils, CertificateParseException

TEST_DATA_DIR = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "data")
LOG = logging.getLogger(__name__)


class CertUtilsTest(TestCase):
    """
    Tests to exercise splice.common.certs.CertUtils
    """
    def setUp(self):
        super(CertUtilsTest, self).setUp()
        # Test Certificate Data
        # invalid cert, signed by a CA other than 'root_ca_pem'
        self.invalid_identity_cert_pem = os.path.join(TEST_DATA_DIR, "invalid_cert", "invalid.cert")
        self.invalid_identity_cert_pem = open(self.invalid_identity_cert_pem, "r").read()
        # a valid cert, signed by the below CA, 'root_ca_pem'
        self.valid_identity_cert_path =  os.path.join(TEST_DATA_DIR, "valid_cert", "valid.cert")
        self.valid_identity_cert_pem = open(self.valid_identity_cert_path, "r").read()
        # CA
        self.root_ca_crt_path = os.path.join(TEST_DATA_DIR, 'ca', 'ca.crt')
        self.root_ca_key_path = os.path.join(TEST_DATA_DIR, 'ca', 'ca.key')
        self.root_ca_srl_path = os.path.join(TEST_DATA_DIR, 'ca', 'ca.srl')
        self.root_ca_crt = open(self.root_ca_crt_path).read()
        self.root_ca_key = open(self.root_ca_key_path).read()
        self.root_ca_pem = open(self.root_ca_srl_path).read()
        self.root_ca_pem = self.root_ca_crt + self.root_ca_key

        self.expected_valid_identity_uuid = "fb647f68-aa01-4171-b62b-35c2984a5328"

        self.cert_utils = CertUtils()

    def tearDown(self):
        super(CertUtilsTest, self).tearDown()

    def test_validate_certificate_pem_valid(self):
        self.assertTrue(self.cert_utils.validate_certificate(
            self.valid_identity_cert_pem, self.root_ca_pem))

    def test_validate_certificate_pem_invalid(self):
        self.assertFalse(self.cert_utils.validate_certificate(
            self.invalid_identity_cert_pem, self.root_ca_pem))

    def test_get_subject_pieces(self):
        pieces = self.cert_utils.get_subject_pieces(self.valid_identity_cert_pem)
        self.assertTrue(pieces["CN"])
        self.assertEquals(pieces["CN"], self.expected_valid_identity_uuid)

    def test_get_subject_pieces_with_filepath(self):
        caught = False
        try:
            pieces = self.cert_utils.get_subject_pieces(self.valid_identity_cert_path)
        except CertificateParseException, e:
            caught = True
        self.assertTrue(caught)
