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


from setuptools import setup, find_packages

setup(
    name='python-certutils',
    version='0.1',
    license='GPLv2+',
    author='Splice Team - Red Hat',
    author_email='splice-devel@redhat.com',
    description='Common code for manipulating X.509 certificates',
    url='https://github.com/splice/python-certutils.git',
    packages=find_packages(),
)
