#!/usr/bin/env python3
# File name: pynacl_test.py
# Description: Test vectors run through libsodium through pynacl

import nacl.encoding
import nacl.signing
from nacl.signing import VerifyKey
import json


with open('cases.json') as json_file:
    data = json.load(json_file)
    for (i, p) in enumerate(data):
        public_key = VerifyKey(p['pub_key'], encoder=nacl.encoding.HexEncoder)
        msg = bytes.fromhex(p['message'])
        sig = bytes.fromhex(p['signature'])

        try:
            public_key.verify(msg, sig)
            print(f"vector {i}: true")
        except nacl.exceptions.CryptoError:
            print(f"vector {i}: false")
