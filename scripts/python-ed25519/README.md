This code tests the python-ed25519 (https://github.com/warner/python-ed25519) that binds to
the C code of the SUPERCOP benchmark suite (http://bench.cr.yp.to/supercop.html).
To run this test:
> git clone git@github.com:warner/python-ed25519.git
Add the test below to src/ed25519/test_ed25519.py
> python setup.py build
> python setup.py test
