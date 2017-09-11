from setuptools import find_packages, setup

with open('coinflow/__init__.py', 'r') as f:
    for line in f:
        if line.startswith('__version__'):
            version = line.strip().split('=')[1].strip(' \'"')
            break
    else:
        version = '0.0.1'

with open('README.rst', 'rb') as f:
    readme = f.read().decode('utf-8')

REQUIRES = []

setup(
    name='coinflow',
    version=version,
    description='Node for Bitcoin transaction geolocation network',
    long_description=readme,
    author='Mariusz Litwin',
    author_email='mariuszlitwin@hotmail.com',
    maintainer='Mariusz Litwin',
    maintainer_email='mariuszlitwin@hotmail.com',
    url='https://github.com/_/coinflow',
    license='MIT/Apache-2.0',

    keywords=[
        '',
    ],

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: No Input/Output (Daemon)'
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
    ],

    install_requires=REQUIRES,
    tests_require=['coverage', 'pytest'],

    packages=find_packages(),
)
