#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'
import hashlib


def md5sum(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest().upper()


def main():
    pass


if __name__ == '__main__':
    main()