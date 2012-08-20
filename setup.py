from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(
    name='tegola',
    version=version,
    description="HUBS Project Network Management",
    long_description="""\
HUBS Project Network Management
""",
    # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Framework :: Paste",
        "Framework :: Pylons",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 2.6",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="snmp network management",
    author='William Waites',
    author_email='wwaites@tardis.ed.ac.uk',
    url="http://tegola.org.uk/",
    license='AGPL',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        "setuptools",
        "pymongo",
        "netsnmp_python",
        "pexpect",
        "werkzeug",
        "flup",
    ],
    entry_points="""
        # -*- Entry points: -*-
        [console_scripts]
        tegola=tegola.cmd:_cli
    """,
)
