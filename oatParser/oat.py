#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'

from oatParser.meta import MetaClass
from util.util import *
import struct

class OatHeader(MetaClass):
    __fields_info__ = (
        ("magic_", "4s"),
        ("version", "4s"),
        ("adler32_checksum_", "I"),
        ("instruction_set_", "I"),
        ("instruction_set_features_", "I"),
        ("dex_file_count_", "I"),  # dex file count
        ("executable_offset_", "I"),
        ("interpreter_to_interpreter_bridge_offset_", "I"),
        ("interpreter_to_compiled_code_bridge_offset_", "I"),
        ("jni_dlsym_lookup_offset_", "I"),
        ("portable_imt_conflict_trampoline_offset_", "I"),
        ("portable_resolution_trampoline_offset_", "I"),
        ("portable_to_interpreter_bridge_offset_", "I"),
        ("quick_generic_jni_trampoline_offset_", "I"),
        ("quick_imt_conflict_trampoline_offset_", "I"),
        ("quick_resolution_trampoline_offset_", "I"),
        ("quick_to_interpreter_bridge_offset_", "I"),
        ("image_patch_delta_", "I"),
        ("image_file_location_oat_checksum_", "I"),
        ("image_file_location_oat_data_begin_", "I"),
        ("key_value_store_size_", "I"),  #
    )

    def __init__(self, buf):
        self.unpack(buf)
        self.key_value_store_ = None

    def get_dex_count(self):
        return self.dex_file_count_

    def get_key_value_store_size(self):
        return self.key_value_store_size_

    def set_key_value_store(self, key_value_store):
        self.key_value_store_ = key_value_store


class OatHeaderM(OatHeader):
    __fields_info__ = (
        ("magic_", "4s"),
        ("version", "4s"),
        ("adler32_checksum_", "I"),
        ("instruction_set_", "I"),
        ("instruction_set_features_", "I"),
        ("dex_file_count_", "I"),  # dex file count
        ("executable_offset_", "I"),
        ("interpreter_to_interpreter_bridge_offset_", "I"),
        ("interpreter_to_compiled_code_bridge_offset_", "I"),
        ("jni_dlsym_lookup_offset_", "I"),
        # ("portable_imt_conflict_trampoline_offset_", "I"), # OatHeader does not contains thoes fields in adnroid 6
        # ("portable_resolution_trampoline_offset_", "I"),
        # ("portable_to_interpreter_bridge_offset_", "I"),
        ("quick_generic_jni_trampoline_offset_", "I"),
        ("quick_imt_conflict_trampoline_offset_", "I"),
        ("quick_resolution_trampoline_offset_", "I"),
        ("quick_to_interpreter_bridge_offset_", "I"),
        ("image_patch_delta_", "I"),
        ("image_file_location_oat_checksum_", "I"),
        ("image_file_location_oat_data_begin_", "I"),
        ("key_value_store_size_", "I"),  #
    )

    def __init__(self, buf):
        super(OatHeaderM, self).__init__(buf)


class DexHeader(MetaClass):
    __fields_info__ = (
        ("magic_", "8s"),
        ("checksum_", "I"),
        ("signature_", "20s"),
        ("file_size_", "I"),  # size of entire file
        ("header_size_", "I"),
        ("endian_tag_", "I"),
        ("link_size_", "I"),
        ("link_off_", "I"),
        ("map_off_", "I"),
        ("string_ids_size_", "I"),
        ("string_ids_off_", "I"),
        ("type_ids_size_", "I"),
        ("type_ids_off_;", "I"),
        ("proto_ids_size_", "I"),
        ("proto_ids_off_", "I"),
        ("field_ids_size_", "I"),
        ("field_ids_off_", "I"),
        ("method_ids_size_", "I"),
        ("method_ids_off_", "I"),
        ("class_defs_size_", "I"),  # number of ClassDefs
        ("class_defs_off_", "I"),
        ("data_size_", "I"),
        ("data_off_", "I")
    )

    def __init__(self, buf):
        self.unpack(buf)
        self.dex_file_data = None
        self.path_in_device = None

    def set_path_in_device(self, path_in_device):
        self.path_in_device = path_in_device

    def get_path_in_device(self):
        return self.path_in_device

    def get_file_size(self):
        return self.file_size_

    def get_class_defs_size(self):
        return self.class_defs_size_

    def set_dex_file_data(self, dex_file_data):
        self.dex_file_data = dex_file_data

    def get_dex_file_data(self, is_fix_checksum=False):
        if is_fix_checksum:
            return self.__fix_dex_checksum()
        else:
            return self.dex_file_data

    def __fix_dex_checksum(self):
        fixed_data = self.__fix_sha1(self.dex_file_data)
        fixed_data = self.__fix_adler32_checksum(fixed_data)
        return fixed_data

    # ("magic_", "8s"),
    # ("checksum_", "I"), 4bytes
    # ("signature_", "20s"),
    def __fix_sha1(self, dex_file_data):
        if not dex_file_data:
            raise Exception("The dex file data is null!")

        sha1 = sha1_digest(dex_file_data[32:])
        return dex_file_data[0:12] + sha1 + dex_file_data[32:]

    def __fix_adler32_checksum(self, dex_file_data):
        if not dex_file_data:
            raise Exception("The dex file data is null!")

        adler32 = adler32_checksum(dex_file_data[12:])
        return dex_file_data[0:8] + struct.pack("i", adler32) + dex_file_data[12:]


def main():
    pass


if __name__ == '__main__':
    main()