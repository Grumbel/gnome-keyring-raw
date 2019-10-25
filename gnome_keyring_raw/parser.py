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


import io

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from gnome_keyring_raw.binary_reader import BinaryReader


class Parser:

    def __init__(self, fin, password):
        self._reader = BinaryReader(fin)
        self._password = password

    def parse(self):
        r = self._reader

        r.expect_bytes(b"GnomeKeyring\n\r\0\n")

        class Keyring: pass
        keyring = Keyring()
        keyring.version = r.read_bytes(2)
        keyring.crypto_algo = r.read_bytes(1)[0]
        keyring.hash_algo = r.read_bytes(1)[0]

        if keyring.crypto_algo != 0:  # assume AES128
            raise Exception("unknown crypto algo")

        if keyring.hash_algo != 0:  # assume SHA256
            raise Exception("unknown hash algo")

        keyring.name = r.read_string()
        keyring.ctime = r.read_time_t()
        keyring.mtime = r.read_time_t()

        keyring.flags = r.read_guint32()
        keyring.lock_timeout = r.read_guint32()
        keyring.hash_iterations = r.read_guint32()
        keyring.salt = r.read_bytes(8)
        keyring.reserved = r.read_guint32s(4)

        print("crypto:", keyring.crypto_algo)
        print("hash:", keyring.hash_algo)
        print("salt:", keyring.salt)
        print("hash_iterations:", keyring.hash_iterations)

        keyring.num_items = r.read_guint32()

        for _ in range(keyring.num_items):
            class Item: pass
            item = Item()
            item.id = r.read_guint32()
            item.type = r.read_guint32()
            item.num_attributes = r.read_guint32()
            print("item.num_attributes:", item.num_attributes)
            for _ in range(item.num_attributes):
                class Attribute: pass
                attribute = Attribute()
                attribute.name = r.read_string()
                attribute.type = r.read_guint32()
                print("attribute.name:", attribute.name)
                if attribute.type == 0:
                    attribute.hash = r.read_string()
                    print("HASH:", attribute.hash)
                elif attribute.type == 1:
                    attribute.hash = r.read_guint32()
                else:
                    raise Exception("unknown attribute type")
        keyring.num_encrypted_bytes = r.read_guint32()
        # for _ in range(keyring.num_encrypted_bytes):

        encrypted_bytes = r.read_bytes(keyring.num_encrypted_bytes)
        # print(encrypted_bytes)
        # print(len(pw))
        #if(!egg_symkey_generate_simple (calgo, halgo, password, n_password,
        #   salt, n_salt, iterations, &key, &iv)) {
        digest = b''
        digests = b''
        for _ in range(1):
            sha256 = SHA256.new(data=digest)
            sha256.update(self._password)
            sha256.update(keyring.salt)

            for _ in range(1, keyring.hash_iterations):
                sha256 = SHA256.new(data=sha256.digest())

            digest = sha256.digest()
            print("LEN", len(digest)) # 32

            digests += digest

        print(digests)
        key = digests[0:16]
        iv = digests[16:16+16]  # 16
        aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted = aes.decrypt(encrypted_bytes)
        print("Result:", decrypted[0:300])
        print("Rest:", r._fin.read())

        print("LENGTH:", len(decrypted))
        b_r = io.BytesIO(decrypted)
        enc_r = BinaryReader(b_r)

        encrypted_hash = enc_r.read_bytes(16)
        print("encrypted_hash:", encrypted_hash)

        for _ in range(keyring.num_items):
            name = enc_r.read_string()
            secret = enc_r.read_string()
            ctime = enc_r.read_time_t()
            mtime = enc_r.read_time_t()
            print("name:", name)
            print("secret:", secret)

            reserved = enc_r.read_string()
            reserved_int = enc_r.read_guint32s(4)

            num_attributes = enc_r.read_guint32()
            print("num_attributes:", num_attributes)
            for _ in range(num_attributes):
                name = enc_r.read_string()
                type = enc_r.read_guint32()
                if type == 0:
                    value = enc_r.read_string()
                elif type == 1:
                    value = enc_r.read_guint32()
                else:
                    raise Exception("unknown attribute type")
            acl_len = enc_r.read_guint32()
            for _ in range(acl_len):
                types_allowed = enc_r.read_guint32()
                display_name = enc_r.read_string()
                pathname = enc_r.read_string()
                reserved_str = enc_r.read_string()
                reserved_uint32 = enc_r.read_guint32()

            # zero padding


# EOF #
