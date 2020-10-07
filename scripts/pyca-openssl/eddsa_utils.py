# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the APACHE 2.0 license found in
# the LICENSE file in the root directory of this source tree.
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519

if __name__ == "__main__":
    with open('cases.json') as f:
        data = json.load(f)
#    print('backend version text: ' + default_backend().openssl_version_text())
#    print('backend version num: {}'.format(default_backend().openssl_version_number()))
    output = '\n|PyCA           |'
    for i, test_case in enumerate(data):
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(test_case['pub_key']))
            msg = bytes.fromhex(test_case['message'])
            sig = bytes.fromhex(test_case['signature'])
            pub_key.verify(sig, msg)
            output = output + ' V |'
        except:
            output = output + ' X |'
    output = output + '\n'
    print(output + '\n')
