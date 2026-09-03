package com.ssoplatform.idp.application.usecase.mfa;

/**
 * Minimal RFC 4648 Base32 encoder (unpadded, uppercase) - the encoding every authenticator app
 * expects for a TOTP secret's manual-entry form and {@code otpauth://} URI. Package-private: only
 * {@link EnrollTotpUseCase} needs it, to present a freshly generated raw secret to the user; no
 * other layer ever needs to go from raw secret bytes to this text form.
 *
 * <p>{@link EnrollTotpUseCase#SECRET_BYTE_LENGTH} (20 bytes = 160 bits) is a deliberate multiple of
 * 5 bits, so encoding a secret never produces leftover bits requiring padding - only decoding is
 * not implemented at all, since this system never needs to go the other direction (the secret
 * itself is always carried internally as raw bytes, encrypted at rest - see {@code
 * TotpSecretEncryptor} - never reconstructed from this display form).
 */
final class Base32 {

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Base32() {}

    static String encode(byte[] data) {
        StringBuilder sb = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                sb.append(ALPHABET.charAt(index));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            sb.append(ALPHABET.charAt(index));
        }
        return sb.toString();
    }
}
