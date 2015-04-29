import os
from setuptools import setup

from riker.version import VERSION

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='riker',
    version=VERSION,
    packages=['riker'],
    install_requires=[
        "boto == 2.31.1",
        "docopt == 0.6.2",
        "Fabric == 1.10.1",
        "giturlparse.py == 0.0.5",
        "pybars==0.0.4",
        "tld==0.6.4"
    ],
    entry_points={
        'console_scripts': [
            'riker = riker.main:main',
        ]
    },
    author='Jimmy Schementi',
    author_email='jimmy@schementi.com',
    url='https://github.com/jschementi/riker',
    description='Deploy any application to AWS',
    long_description=README,
    keywords='aws deploy paas scale',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Software Distribution',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities'
    ]
)
