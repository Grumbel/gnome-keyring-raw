#!/usr/bin/env python3

# gnome-keyring-raw - Inspect raw Gnome keyring files
# Copyright (C) 2019 Ingo Ruhnke <grumbel@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import argparse
import getpass
import sys

from typing import List

from gnome_keyring_raw.parser import Parser


def parse_args(args: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect raw Gnome keyring files")
    parser.add_argument("-p", "--password", metavar="STRING", default=None,
                        help="Password used to decrypt the file")
    parser.add_argument("FILE", nargs=1, help="Gnome keyring file to read")
    return parser.parse_args(args)


def main(argv: List[str]):
    args = parse_args(argv[1:])

    for filename in args.FILE:
        password = getpass.getpass().encode("utf-8")

        with open(filename, "rb") as fin:
            parser = Parser(fin, password)
            parser.parse()


def main_entrypoint():
    main(sys.argv)


if __name__ == "__main__":
    main_entrypoint()


# EOF #
