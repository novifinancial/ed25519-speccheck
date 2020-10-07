// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

const crypto = require("crypto");

const jsonfile = require('jsonfile')
const file = '../../cases.json'
jsonfile.readFile(file, function (err, test_vector) {
  if (err) console.error(err)
  // console.log(test_vector);
  let output = "\n|npm            |";
  for (let i = 0; i < test_vector.length; i++) {
    let pub_key = toPem(test_vector[i].pub_key);
    let message = Buffer.from(test_vector[i].message, "hex");
    let signature = Buffer.from(test_vector[i].signature, "hex");
    // console.log(i + ": " + crypto.verify(null, message, pub_key, signature));
    if (crypto.verify(null, message, pub_key, signature)) {
      output += " V |";
    } else {
      output += " X |";
    }
  }
  console.log(output + "\n");

  function toPem(hexKey) {
    let buf1 = Buffer.from("302a300506032b6570032100", "hex");
    let buf2 = Buffer.from(hexKey, "hex");
    let keyBuf = Buffer.from(
      "-----BEGIN PUBLIC KEY-----\n" +
        Buffer.concat([buf1, buf2]).toString("base64") +
        "\n-----END PUBLIC KEY-----"
    );

    return crypto.createPublicKey(keyBuf);
  }
});
