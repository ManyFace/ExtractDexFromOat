#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'
import hashlib
import zlib


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


class AndroidVersion:
    ANDROIDL = "androidL"
    ANDROIDM = "androidM"
    ANDROIDN = "androidN"
    CURRENT_VERSION = ANDROIDL

    @classmethod
    def set_version(cls, version):
        if version == "L":
            cls.CURRENT_VERSION = cls.ANDROIDL
        elif version == "M":
            cls.CURRENT_VERSION = cls.ANDROIDM
        elif version == "N":
            cls.CURRENT_VERSION = cls.ANDROIDN
        else:
            raise Exception("unknown android version")

    @classmethod
    def get_verison(cls):
        return cls.CURRENT_VERSION


def main():
    pass


if __name__ == '__main__':
    main()