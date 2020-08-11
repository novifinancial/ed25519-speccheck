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
  
  print("case \(index), \(rawPubKey.isValidSignature(signature, for: message))")
}

verifySignature(
  index: 0,
  message: "2a66241a42a9ee12994d8068dcf1bb7dfc6637b45450acd43711f637fa5080fc",
  pubKey: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  signature: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000"
)

verifySignature(
  index: 1,
  message: "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
  pubKey: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  signature: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000"
)

verifySignature(
  index: 2,
  message: "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
  pubKey: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  signature: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"
)

verifySignature(
  index: 3,
  message: "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
  pubKey: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  signature: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"
)

verifySignature(
  index: 4,
  message: "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
  pubKey: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
  signature: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa182ef1a5b928da07fec769cc8a12db6bcf70dab3f3227fa315e9d5e3e01a3405"
)

verifySignature(
  index: 5,
  message: "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
  pubKey: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
  signature: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e"
)

verifySignature(
  index: 6,
  message: "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
  pubKey: "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
  signature: "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"
)

verifySignature(
  index: 7,
  message: "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
  pubKey: "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
  signature: "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"
)

verifySignature(
  index: 8,
  message: "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
  pubKey: "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
  signature: "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"
)

verifySignature(
  index: 9,
  message: "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
  pubKey: "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
  signature: "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514"
)


//Output
//
//case 0, false
//case 1, true
//case 2, false
//case 3, true
//case 4, false
//case 5, true
//case 6, false
//case 7, true
//case 8, false
//case 9, false
