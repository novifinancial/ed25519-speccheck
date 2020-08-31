# This code tests the python-ed25519 (https://github.com/warner/python-ed25519) that binds to
# the C code of the SUPERCOP benchmark suite (http://bench.cr.yp.to/supercop.html).
# To run this test:
# > git clone git@github.com:warner/python-ed25519.git
# Add the test below to src/ed25519/test_ed25519.py
# > python setup.py build
# > python setup.py test
# The output is:
# 0: false
# 1: true
# 2: false
# 3: true
# 4: false
# 5: true
# 6: false
# 7: true
# 8: false
# 9: true
# 10: true
# 11: false
# 12: false

# import json


def test_ours(self):
    with open('../cases.json') as f:
        data = json.load(f)
        print('File loaded')
    for i, test_case in enumerate(data):
        try:
            pub_key = ed25519.VerifyingKey(bytes.fromhex(test_case['pub_key']))
            msg = bytes.fromhex(test_case['message'])
            sig = bytes.fromhex(test_case['signature'])
            pub_key.verify(sig, msg)
            print('{}: true'.format(i))
        except:
            print('{}: false'.format(i))
