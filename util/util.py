#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'
import hashlib
import zlib
import struct


def md5sum(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest().upper()


def sha1_digest(data):
    sha1 = hashlib.sha1()
    sha1.update(data)
    return sha1.digest()  # str


def adler32_checksum(data):
    adler32 = zlib.adler32(data)
    return adler32  # signed int, 4bytes


def main():
    pass


if __name__ == '__main__':
    main()