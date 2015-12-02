#!/usr/bin/env python
# encoding=utf-8
__author__ = 'cpf'

import argparse
import os

from oatParser.oat_parser import OatParser


def main():
    arg_parser = argparse.ArgumentParser(description="Oat Parser")
    arg_parser.add_argument("-f", dest="oat_file_path", required=True, help="the oat file path")
    args = arg_parser.parse_args()

    oat_file_path = args.oat_file_path
    if not os.path.exists(oat_file_path):
        print "Error: " + oat_file_path + " doesn't exist!" + os.linesep
        return

    try:
        oat_parser = OatParser(oat_file_path)
        oat_parser.parse()
        oat_parser.save_dex_files()
    except Exception, ex:
        print "Error: " + str(ex)


if __name__ == '__main__':
    main()