// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

import CryptoKit
import Foundation

extension String {

  /// Create `Data` from hexadecimal string representation
  ///
  /// This creates a `Data` object from hex string. Note, if the string has any spaces or non-hex characters (e.g. starts with '<' and with a '>'), those are ignored and only hex characters are processed.
  ///
  /// - returns: Data represented by this hexadecimal string.

  var hexadecimal: Data? {
    var data = Data(capacity: count / 2)

    let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
    regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
      let byteString = (self as NSString).substring(with: match!.range)
      let num = UInt8(byteString, radix: 16)!
      data.append(num)
    }

    guard data.count > 0 else { return nil }

    return data
  }
}

func verifySignature(index: Int, message: String, pubKey: String, signature: String) {
  let message = message.hexadecimal!
  let pubKeyData = pubKey.hexadecimal!
  let signature = signature.hexadecimal!


  let rawPubKey = try! Curve25519.Signing.PublicKey(rawRepresentation: pubKeyData)

  if (rawPubKey.isValidSignature(signature, for: message)) {
    print(" V |", terminator:"")
  } else {
    print(" X |", terminator:"")
  }
  // print("case \(index), \(rawPubKey.isValidSignature(signature, for: message))")
}

struct TestVector: Codable {
    let message: String
    let pub_key: String
    let signature: String
}

let path = "../../cases.json"
let JSON = try! NSString(contentsOfFile: path, encoding: String.Encoding.ascii.rawValue) as String
let jsonData = JSON.data(using: .utf8)
let test_vectors = try! JSONDecoder().decode(Array<TestVector>.self, from: jsonData!)

print("|CryptoKit      |", terminator:"")

var i = 0
for tv in test_vectors {
  verifySignature(
    index: i,
    message: tv.message,
    pubKey: tv.pub_key,
    signature: tv.signature
  )
  i += 1
}
print("")
