/** Encoding utils for cryptographic material. **/
public class EncodingUtils {

    /** Get X509 format of a compressed Edwards point (public key). **/
    public static byte[] compressedEd25519PublicKeyToX509(byte[] compressedPublicKey) {
        int totlen = 12 + compressedPublicKey.length;
        byte[] rv = new byte[totlen];
        int idx = 0;
        // sequence
        rv[idx++] = 0x30;
        rv[idx++] = (byte) (totlen - 2);
        // Algorithm Identifier
        // sequence
        rv[idx++] = 0x30;
        rv[idx++] = 5;
        // OID
        // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809%28v=vs.85%29.aspx
        rv[idx++] = 0x06;
        rv[idx++] = 3;
        rv[idx++] = 43;
        rv[idx++] = 101;
        rv[idx++] = (byte) 112;
        // params - absent
        // the key
        rv[idx++] = 0x03; // bit string
        rv[idx++] = (byte) (1 + compressedPublicKey.length);
        rv[idx++] = 0; // number of trailing unused bits
        System.arraycopy(compressedPublicKey, 0, rv, idx, compressedPublicKey.length);
        return rv;
    }
}
