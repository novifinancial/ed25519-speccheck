Tweetnacl version 1.0.3 (https://www.npmjs.com/package/tweetnacl)

To reproduce the results run `node test.js`.

Output
0: false
1: true
2: false
3: true
4: false
5: true
6: false
7: true
8: false
9: true
10: true
11: false
12: false

Case 9 is interesting as it shows the violation of `S <= L` requirement for a valid signature.
