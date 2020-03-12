from setuptools import setup
from setuptools import find_packages

setup(name='pyaoscx',
      version='0.1.0',
      description='AOS-CX Python Modules',
      url='https://github.com/aruba/pyaoscx',
      author='Aruba Switching Automation',
      author_email='aruba-switching-automation@hpe.com',
      license='Apache 2.0',
    classifiers=[

        'Development Status :: 4 - Beta',

        'Intended Audience :: System Administrators',
        'Topic :: System :: Networking',

        'License :: OSI Approved :: Apache Software License',

        'Programming Language :: Python :: 3 :: Only'
    ],
    keywords='networking aruba aos-cx switch rest api python',
    packages=find_packages(exclude=['docs']),
    install_requires=['requests', 'PyYAML'],
      zip_safe=False)