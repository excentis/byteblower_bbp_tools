#!/usr/bin/env python

import setuptools
setuptools.setup(
    name='byteblower_bbp_tools',
    version='0.0.1',
    author="Excentis ByteBlower Development Team",
    author_email="support.byteblower@excentis.com",
    url="https://www.byteblower.com",
    description="Minimal ByteBlower project manipulation tools",
    packages=setuptools.find_namespace_packages(where="src"),
    package_dir={"": "src"},
    license="BSD-3-Clause",
    python_requires=">=3.5,<4",
    project_urls={'setup pages': 'https://setup.byteblower.com'},
    keywords="excentis byteblower",
    install_requires=[
        'lxml',
        'scapy'
    ]
)

