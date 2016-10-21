#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'

import struct
import os

from util.util import *


class Meta(type):
    def __new__(cls, cls_name, cls_basees, clsDict):
        if "__fields_info__" in clsDict:
            fields_info = clsDict["__fields_info__"]
            # clsDict["__slots__"] = [x[0] for x in fields_info]
            t = type.__new__(cls, cls_name, cls_basees, clsDict)
            t.__fields__ = [x[0] for x in fields_info]
            t.__fmt__ = getattr(t, '__byte_order__', "<") + "".join([x[1] for x in fields_info])  # default little endian
            t.__byte_size__ = struct.calcsize(t.__fmt__)
            return t
        else:
            return type.__new__(cls, cls_name, cls_basees, clsDict)

    def __len__(self):
        return self.__byte_size__


class MetaClass():
    __metaclass__ = Meta

    def unpack(self, buf):
        if len(buf) < self.__byte_size__:
            raise Exception("invalid " + self.__class__.__name__)

        for attr, value in zip(self.__fields__, struct.unpack(self.__fmt__, buf[:self.__byte_size__])):
            setattr(self, attr, value)

    def __str__(self):
        fmt_str = self.__class__.__name__ + "=>" + os.linesep
        for attr in self.__fields__:
            attr_value = getattr(self, attr)
            if isinstance(attr_value, str):
                fmt_str += "\t" + attr + "=" + attr_value.encode("hex") + os.linesep
            elif isinstance(attr_value, int):
                fmt_str += "\t" + attr + "=" + str(hex(attr_value)) + os.linesep
            else:
                fmt_str += "\t" + attr + "=" + str(attr_value) + os.linesep

        return fmt_str


class Table():
    def __init__(self, EntryClass):
        self.EntryClass = EntryClass
        self.entries = []

    def init_table(self, buf, entry_num, entry_size):
        for x in xrange(0, entry_num):
            start_index = x * entry_size
            end_index = start_index + entry_size
            entry = self.EntryClass(buf[start_index:end_index])
            self.entries.append(entry)


def main():
    pass


if __name__ == '__main__':
    main()