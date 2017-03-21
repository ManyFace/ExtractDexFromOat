#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'

import re
import os

from oatParser.meta import MetaClass, Table


class Elf64Header(MetaClass):
    __fields_info__ = (
        ("e_ident", "16s"),
        ("e_type", "H"),
        ("e_machine", "H"),
        ("e_version", "I"),
        ("e_entry", "Q"),
        ("e_phoff", "Q"),  # program header table offset
        ("e_shoff", "Q"),  # section header table offset
        ("e_flags", "I"),
        ("e_ehsize", "H"),  # size of elf header
        ("e_phentsize", "H"),  # size of an entry in the program header table
        ("e_phnum", "H"),  # Number of entries in the program header table
        ("e_shentsize", "H"),  # Size of an entry in the section header table
        ("e_shnum", "H"),  # Number of entries in the section header table
        ("e_shstrndx", "H")  # Sect hdr table index of sect name string table
    )

    def __init__(self, buf):
        self.unpack(buf)

    def is_32bit(self):
        '''
        if elf is 32 bit
        :return: True:32bit, False: 64bit
        '''
        EI_CLASS = 4
        ei_class_value = ord(self.e_ident[EI_CLASS])
        if ei_class_value == 1:
            return True
        elif ei_class_value == 2:
            return False
        raise Exception("unknown EI_CLASS:%d" % (ei_class_value))

    def get_phdr_table_offset(self):
        return self.e_phoff

    def get_phdr_table_entry_size(self):
        return self.e_phentsize

    def get_phdr_table_entry_num(self):
        return self.e_phnum

    def get_shdr_table_offset(self):
        return self.e_shoff

    def get_shdr_table_entry_size(self):
        return self.e_shentsize

    def get_shdr_table_entry_num(self):
        return self.e_shnum

    def get_phdr_table_size(self):
        return self.e_phentsize * self.e_phnum

    def get_shdr_table_size(self):
        return self.e_shentsize * self.e_shnum

    def get_sect_name_str_table_index(self):
        return self.e_shstrndx


class Elf64Phdr(MetaClass):  # program header
    __fields_info__ = (
        ("p_type", "I"),
        ("p_flags", "I"),
        ("p_offset", "Q"),  # File offset where segment is located, in bytes
        ("p_vaddr", "Q"),
        ("p_paddr", "Q"),
        ("p_filesz", "Q"),  # Num. of bytes in file image of segment (may be zero)
        ("p_memsz", "Q"),
        ("p_align", "Q")
    )

    def __init__(self, buf):
        self.unpack(buf)


class Pht64(Table):  # ProgramHeaderTable
    def __init__(self):
        Table.__init__(self, Elf64Phdr)


class Elf64Shdr(MetaClass):  # section header
    __fields_info__ = (
        ("sh_name", "I"),  # Section name (index into string table)
        ("sh_type", "I"),  # Section type (SHT_*)
        ("sh_flags", "Q"),
        ("sh_addr", "Q"),
        ("sh_offset", "Q"),  # File offset of section data, in bytes
        ("sh_size", "Q"),  # Size of section, in bytes
        ("sh_link", "I"),
        ("sh_info", "I"),
        ("sh_addralign", "Q"),
        ("sh_entsize", "Q"),  # Size of records contained within the section
    )

    # class Type:  # part of types
    # SHT_NULL = 0  # No associated section (inactive entry).
    # SHT_PROGBITS = 1  # Program-defined contents.
    # SHT_SYMTAB = 2  # Symbol table.
    # SHT_STRTAB = 3  # String table.
    # SHT_RELA = 4  # Relocation entries; explicit addends.
    # SHT_HASH = 5  # Symbol hash table.
    # SHT_DYNAMIC = 6  # Information for dynamic linking.
    # SHT_NOBITS = 8  # Data occupies no space in the file.
    # SHT_DYNSYM = 11  # Symbol table.

    def __init__(self, buf):
        self.unpack(buf)
        self.name = ""

    def get_size(self):
        return self.sh_size

    def get_offset(self):
        return self.sh_offset

    def get_entry_size(self):
        return self.sh_entsize

    def get_entry_num(self):
        if not self.sh_size:
            return 0
        if not self.sh_entsize:
            return 1
        return self.sh_size / self.sh_entsize

    def set_name(self, name):
        if name:
            self.name = name

    def get_name(self):
        return self.name

    def get_addr(self):
        return self.sh_addr


class Sht64(Table):  # SectionHeaderTable
    def __init__(self):
        Table.__init__(self, Elf64Shdr)
        self.headers_dict = {}  # {sect_name:header}

    def set_section_name(self, string_table):
        if not string_table.is_sect_name_string_table():
            raise Exception("string table is not section name string table!")

        for shdr in self.entries:
            shdr.set_name(string_table.get_string(shdr.sh_name))
            self.headers_dict[shdr.get_name()] = shdr

    def get_string_table_shdr(self):
        return self.headers_dict.get(".dynstr", None)

    def get_symbol_table_shdr(self):
        return self.headers_dict.get(".dynsym", None)

    def get_entries(self):
        return self.entries

    def get_by_index(self, index):
        return self.entries[index]


class Elf64Sym(MetaClass):
    __fields_info__ = (
        ("st_name", "I"),  # Symbol name (index into string table)
        ("st_info", "B"),
        ("st_other", "B"),
        ("st_shndx", "H"),  # Which section (header table index) it's defined
        ("st_value", "Q"),  # Value or address associated with the symbol
        ("st_size", "Q"),  # Size of the symbol
    )

    def __init__(self, buf):
        self.unpack(buf)
        self.name = ""

    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def get_offset(self, shdr_table):
        shdr = shdr_table.get_by_index(self.st_shndx)
        return shdr.get_offset() + self.st_value - shdr.get_addr()

    def get_size(self):
        return self.st_size


class SymbolTable64(Table):
    def __init__(self):
        Table.__init__(self, Elf64Sym)
        self.elf64_syms_dict = {}  # {name:elf64_sym}

    def set_sym_name(self, string_table):
        if string_table.is_sect_name_string_table():
            raise Exception("Should be string table, not section name string table!")

        for elf64_sym in self.entries:
            # set symbol name
            elf64_sym.set_name(string_table.get_string(elf64_sym.st_name))
            self.elf64_syms_dict[elf64_sym.get_name()] = elf64_sym

    def get_oatdata_sym(self):
        return self.elf64_syms_dict.get("oatdata", None)


def main():
    pass


if __name__ == '__main__':
    main()
