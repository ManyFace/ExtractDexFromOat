#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'

import struct

from oatParser.elf import *
from oatParser.oat import *
from util.util import *


class OatParser:
    def __init__(self, oat_file_path):
        self.oat_file_path = oat_file_path
        self.elf32_header = None
        self.phdr_table = None
        self.shdr_table = None
        self.sect_name_str_table = None
        self.string_table = None
        self.symbol_table = None
        self.oat_file = None
        self.dex_headers = []

    def parse(self):
        fileSize = os.path.getsize(self.oat_file_path)
        try:
            self.oat_file = open(self.oat_file_path, "rb")

            # parse elf header
            elf32_header_buf = self.oat_file.read(len(Elf32Header))
            self.elf32_header = Elf32Header(elf32_header_buf)

            # parse program header table
            phdr_table_buf = self.__get_buf(self.elf32_header.get_phdr_table_offset(), self.elf32_header.get_phdr_table_size())
            self.phdr_table = ProgramHeaderTable()
            phdr_table_entry_num = self.elf32_header.get_phdr_table_entry_num()
            phdr_table_entry_size = self.elf32_header.get_phdr_table_entry_size()
            self.phdr_table.init_table(phdr_table_buf, phdr_table_entry_num, phdr_table_entry_size)

            # parse section header table
            shdr_table_buf = self.__get_buf(self.elf32_header.get_shdr_table_offset(), self.elf32_header.get_shdr_table_size())
            self.shdr_table = SectionHeaderTable()
            shdr_table_entry_num = self.elf32_header.get_shdr_table_entry_num()
            shdr_table_entry_size = self.elf32_header.get_shdr_table_entry_size()
            self.shdr_table.init_table(shdr_table_buf, shdr_table_entry_num, shdr_table_entry_size)

            # parse section name string table
            sect_name_header = self.shdr_table.get_entries()[self.elf32_header.get_sect_name_str_table_index()]
            sect_name_str_table_buf = self.__get_buf(sect_name_header.get_offset(), sect_name_header.get_size())
            self.sect_name_str_table = StringTable(sect_name_header, sect_name_str_table_buf, True)

            # set section name
            self.shdr_table.set_section_name(self.sect_name_str_table)

            # parse string table
            string_table_shdr = self.shdr_table.get_string_table_shdr()
            string_table_buf = self.__get_buf(string_table_shdr.get_offset(), string_table_shdr.get_size())
            self.string_table = StringTable(string_table_shdr, string_table_buf)

            # parse symbol table
            symbol_table_shdr = self.shdr_table.get_symbol_table_shdr()
            symbol_table_buf = self.__get_buf(symbol_table_shdr.get_offset(), symbol_table_shdr.get_size())
            self.symbol_table = SymbolTable()
            self.symbol_table.init_table(symbol_table_buf, symbol_table_shdr.get_entry_num(), symbol_table_shdr.get_entry_size())

            # set symbol name
            self.symbol_table.set_sym_name(self.string_table)

            # parse oatdata
            self.__parse_oatdata()

        finally:
            self.__close()

    def save_dex_files(self, is_fix_checksum=False):
        if not self.dex_headers:
            print "There is no dex file."

        saved_file_list = {}
        out_put_dir = os.path.join(os.getcwd(), "out")
        if not os.path.exists(out_put_dir):
            os.mkdir(out_put_dir)

        for dex_header in self.dex_headers:
            dex_data = dex_header.get_dex_file_data(is_fix_checksum)
            md5 = md5sum(dex_data)
            save_name = md5 + ".dex"
            with open(os.path.join(out_put_dir, save_name), "wb") as dex_file:
                dex_file.write(dex_data)
            saved_file_list[save_name] = dex_header

        show_info = os.linesep + "Saved " + str(len(saved_file_list)) + " dex files!" + os.linesep * 2
        show_info += "file list=>" + os.linesep
        str_lens = [len(dex_header.get_path_in_device()) for dex_header in saved_file_list.values()]
        str_lens.append(40)
        max_str_len = max(str_lens)
        show_info += "file_path_in_device".center(max_str_len) + "\t" + "output_name".center(max_str_len) + os.linesep
        for file_name, dex_header in saved_file_list.items():
            show_info += dex_header.get_path_in_device().ljust(max_str_len) + "\t" + file_name.center(max_str_len) + os.linesep
        print show_info


    def __parse_oatdata(self):
        oatdata_sym = self.symbol_table.get_oatdata_sym()
        if not oatdata_sym:
            raise Exception("oatdata doesn't exist")

        # oatHeader
        OatHeaderCompatible = OatHeader
        if AndroidVersion.get_verison() == AndroidVersion.ANDROIDM:
            OatHeaderCompatible = OatHeaderM
        oat_header_buf = self.__get_buf(oatdata_sym.get_offset(self.shdr_table), len(OatHeaderCompatible))
        oat_header = OatHeaderCompatible(oat_header_buf)
        key_value_store = self.oat_file.read(oat_header.get_key_value_store_size())
        oat_header.set_key_value_store(key_value_store)

        # dex
        for dex_index in xrange(0, oat_header.get_dex_count()):
            # dex meta info
            dex_file_location_size = struct.unpack("<I", self.oat_file.read(4))[0]
            dex_file_location = struct.unpack("<" + str(dex_file_location_size) + "s", self.oat_file.read(dex_file_location_size))[0]
            dex_file_checksum = struct.unpack("<I", self.oat_file.read(4))[0]
            dex_file_offset = struct.unpack("<I", self.oat_file.read(4))[0]
            dex_file_offset += oatdata_sym.get_offset(self.shdr_table)

            file_cur_position = self.oat_file.tell()

            # parse dex
            dex_Header_buf = self.__get_buf(dex_file_offset, len(DexHeader))
            dex_header = DexHeader(dex_Header_buf)
            dex_file_data_buf = self.__get_buf(dex_file_offset, dex_header.get_file_size())
            dex_header.set_dex_file_data(dex_file_data_buf)
            dex_header.set_path_in_device(dex_file_location)
            self.dex_headers.append(dex_header)

            self.oat_file.seek(file_cur_position, os.SEEK_SET)  # set file pointer to method offsets

            methods_offsets_pointer_buf = self.oat_file.read(dex_header.get_class_defs_size() * 4)
            methods_offsets_pointers = struct.unpack("<" + str(dex_header.get_class_defs_size()) + "I", methods_offsets_pointer_buf)

    def __close(self):
        if self.oat_file:
            self.oat_file.close()

    def __get_buf(self, offset, buf_size):
        if not self.oat_file:
            raise Exception("file is null!")
        if offset < 0:
            raise Exception("file offset is invalid!")
        if buf_size < 0:
            raise Exception("buffer size is invalid!")

        self.oat_file.seek(offset, os.SEEK_SET)
        return self.oat_file.read(buf_size)


def main():
    oat_file_path = "extra/system@framework@boot.oat"
    oat_parser = OatParser(oat_file_path)
    oat_parser.parse()


if __name__ == '__main__':
    main()