#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'

import argparse
import os
from oatParser.oat_parser import OatParser
from util.util import AndroidVersion


def main():
    arg_parser = argparse.ArgumentParser(description="Oat Parser")
    arg_parser.add_argument("-f", dest="oat_file_path", required=True, help="The oat file path")
    arg_parser.add_argument("-v", dest="android_version", choices=["L", "M", "N"], default="L", help="set android version:L, M or N, default is L")
    arg_parser.add_argument("--fix-checksum", action="store_true", help="Whether fix the checksum of output dex files")
    args = arg_parser.parse_args()

    oat_file_path = args.oat_file_path
    if not os.path.exists(oat_file_path):
        print "Error: " + oat_file_path + " doesn't exist!" + os.linesep
        return

    AndroidVersion.set_version(args.android_version)

    try:
        oat_parser = OatParser(oat_file_path)
        oat_parser.parse()
        oat_parser.save_dex_files(args.fix_checksum)
    except Exception, ex:
        print "Error: " + str(ex)
        print '[+] Please specify -v with other android version!\n[+] Run "python main.py -h" to get more information!\n'

if __name__ == '__main__':
    main()