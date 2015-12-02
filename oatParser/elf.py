#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'

import re
import os

from oatParser.meta import MetaClass, Table


class Elf32Header(MetaClass):
    __fields_info__ = (
        ("e_ident", "16s"),
        ("e_type", "H"),
        ("e_machine", "H"),
        ("e_version", "I"),
        ("e_entry", "I"),
        ("e_phoff", "I"),  # program header table offset
        ("e_shoff", "I"),  # section header table offset
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


class Elf32Phdr(MetaClass):  # program header
    __fields_info__ = (
        ("p_type", "I"),
        ("p_offset", "I"),  # File offset where segment is located, in bytes
        ("p_vaddr", "I"),
        ("p_paddr", "I"),
        ("p_filesz", "I"),  # Num. of bytes in file image of segment (may be zero)
        ("p_memsz", "I"),
        ("p_flags", "I"),
        ("p_align", "I")
    )

    def __init__(self, buf):
        self.unpack(buf)


class ProgramHeaderTable(Table):
    def __init__(self):
        Table.__init__(self, Elf32Phdr)


class Elf32Shdr(MetaClass):  # section header
    __fields_info__ = (
        ("sh_name", "I"),  # Section name (index into string table)
        ("sh_type", "I"),  # Section type (SHT_*)
        ("sh_flags", "I"),
        ("sh_addr", "I"),
        ("sh_offset", "I"),  # File offset of section data, in bytes
        ("sh_size", "I"),  # Size of section, in bytes
        ("sh_link", "I"),
        ("sh_info", "I"),
        ("sh_addralign", "I"),
        ("sh_entsize", "I"),  # Size of records contained within the section
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


class SectionHeaderTable(Table):
    def __init__(self):
        Table.__init__(self, Elf32Shdr)
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


class StringTable():
    def __init__(self, sectHeader, buf, is_section_name=False):
        self.sectHeader = sectHeader
        self.strDict = {}
        self.is_section_name = is_section_name

        self.__parse_section(buf)

    def __check(self, buf):
        buf_hex_str = buf.encode("hex")
        re_compile = re.compile("^00(([1-9A-Fa-f][0-9A-Fa-f])+00)*$")
        re_match = re_compile.match(buf_hex_str)
        if not re_match:
            raise Exception("invalid string table")

    def __parse_section(self, buf):
        if not buf:
            return

        self.__check(buf)

        str_list = buf.split("00".decode("hex"))

        self.strDict[0] = ""
        last_str_index = 0
        for index, value in enumerate(str_list):
            if index == 1:
                self.strDict[1] = value
                last_str_index = 1
            elif 1 < index < len(str_list) - 1:
                self.strDict[last_str_index + len(str_list[index - 1]) + 1] = value
                last_str_index = last_str_index + len(str_list[index - 1]) + 1

    def get_string(self, index):
        if index not in self.strDict:
            raise Exception("index is invalid")
        return self.strDict[index]

    def is_sect_name_string_table(self):
        return self.is_section_name

    def __str__(self):
        fmt_str = self.__class__.__name__
        if self.is_section_name:
            fmt_str += "(Section name String table)=>" + os.linesep
        else:
            fmt_str += "(String table)=>" + os.linesep
        fmt_str += "\tindex\tvalue" + os.linesep
        if not self.strDict:
            fmt_str += "\tstring table is empty" + os.linesep
            return fmt_str

        for key in sorted(self.strDict.keys()):
            fmt_str += "\t" + str(key) + "\t" + str(self.strDict[key]) + os.linesep
        return fmt_str


class Elf32Sym(MetaClass):
    __fields_info__ = (
        ("st_name", "I"),  # Symbol name (index into string table)
        ("st_value", "I"),  # Value or address associated with the symbol
        ("st_size", "I"),  # Size of the symbol
        ("st_info", "B"),
        ("st_other", "B"),
        ("st_shndx", "H"),  # Which section (header table index) it's defined
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


class SymbolTable(Table):
    def __init__(self):
        Table.__init__(self, Elf32Sym)
        self.elf32_syms_dict = {}  # {name:elf32_sym}

    def set_sym_name(self, string_table):
        if string_table.is_sect_name_string_table():
            raise Exception("Should be string table, not section name string table!")

        for elf32_sym in self.entries:
            # set symbol name
            elf32_sym.set_name(string_table.get_string(elf32_sym.st_name))
            self.elf32_syms_dict[elf32_sym.get_name()] = elf32_sym

    def get_oatdata_sym(self):
        return self.elf32_syms_dict.get("oatdata", None)


def main():
    pass


if __name__ == '__main__':
    main()