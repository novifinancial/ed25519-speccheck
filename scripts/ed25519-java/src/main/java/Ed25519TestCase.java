// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

import com.google.gson.annotations.SerializedName;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.MessageDigest;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Ed25519 test case.
 **/
public class Ed25519TestCase {
    @SerializedName(value = "pub_key")
    private final String publicKeyHex;
    @SerializedName(value = "message")
    private final String messageHex;
    @SerializedName(value = "signature")
    private final String signatureHex;

    private final static EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

    public Ed25519TestCase(String publicKeyHex, String messageHex, String signatureHex) {
        this.publicKeyHex = publicKeyHex;
        this.messageHex = messageHex;
        this.signatureHex = signatureHex;
    }

    /**
     * Return EdDSAPublicKey object from the hex representation of the compressed Edwards public key point.
     **/
    private EdDSAPublicKey decodePublicKey() throws InvalidKeySpecException {
        byte[] pk = Utils.hexToBytes(this.publicKeyHex);
        byte[] x509pk = EncodingUtils.compressedEd25519PublicKeyToX509(pk);
        X509EncodedKeySpec encoded = new X509EncodedKeySpec(x509pk);
        return new EdDSAPublicKey(encoded);
    }

    /**
     * Pure Ed25519 signature verification using the i2p lib, it returns false if it fails or if an exception occurs).
     **/
    public boolean verify_i2p() {
        try {
            EdDSAPublicKey publicKey = decodePublicKey();
            byte[] messageBytes = Utils.hexToBytes(this.messageHex);
            byte[] signatureBytes = Utils.hexToBytes(this.signatureHex);
            EdDSAEngine sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
            sgr.initVerify(publicKey);
            return sgr.verifyOneShot(messageBytes, signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Pure Ed25519 signature verification using the BC lib, it returns false if it fails or if an exception occurs).
     **/
    public boolean verify_bc() {
        try {
            Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(
                    Utils.hexToBytes(this.publicKeyHex), 0);
            byte[] messageBytes = Utils.hexToBytes(this.messageHex);
            byte[] signatureBytes = Utils.hexToBytes(this.signatureHex);

            Signer signer = new Ed25519Signer();
            signer.init(false, publicKey);
            signer.update(messageBytes, 0, messageBytes.length);
            return signer.verifySignature(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }
}
