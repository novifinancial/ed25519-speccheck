// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

// import nacl from 'tweetnacl';
// import nacl = require("tweetnacl") // cryptographic functions
// import util = require("tweetnacl-util") // encoding & decoding
nacl = require("tweetnacl");

const fs = require('fs');

let rawdata = fs.readFileSync('cases.json');
let tests = JSON.parse(rawdata);

const fromHexString = hexString =>
      new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

var i;
let output = "\n|TweetNaCl-js   |";
for (i = 0; i < tests.length; i++) {
  let res = nacl.sign.detached.verify(fromHexString(tests[i].message),
                                      fromHexString(tests[i].signature),
                                      fromHexString(tests[i].pub_key));
  output += (res ? " V |" : " X |");
}
console.log(output + "\n");
