package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.TotpSecretEncryptor;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link TotpSecretEncryptor} output port with AES-256-GCM, keyed from {@code
 * app.mfa.totp.encryption-secret} (environment variable {@code TOTP_SECRET_ENCRYPTION_SECRET}).
 *
 * <p>Deliberately its own secret, separate from {@code SIGNING_KEY_ENCRYPTION_SECRET} - see {@code
 * phase_4_1_totp_mfa.md} decision record: leaking one class of encrypted data must never expose
 * the other. Otherwise structurally identical to {@link AesGcmPrivateKeyEncryptorAdapter} - same
 * SHA-256 key derivation from an arbitrary-length configured string, same fresh random 96-bit IV
 * per encryption, prepended to the ciphertext before Base64-encoding.
 */
@Component
public class AesGcmTotpSecretEncryptorAdapter implements TotpSecretEncryptor {

    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private final SecretKeySpec secretKey;

    public AesGcmTotpSecretEncryptorAdapter(@Value("${app.mfa.totp.encryption-secret}") String encryptionSecret) {
        if (encryptionSecret == null || encryptionSecret.isBlank()) {
            throw new IllegalStateException(
                    "app.mfa.totp.encryption-secret (TOTP_SECRET_ENCRYPTION_SECRET) must not be blank");
        }
        this.secretKey = new SecretKeySpec(sha256(encryptionSecret), KEY_ALGORITHM);
    }

    @Override
    public EncryptedTotpSecret encrypt(byte[] rawSecret) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] ciphertext = cipher.doFinal(rawSecret);

            byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
            System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

            return EncryptedTotpSecret.of(Base64.getEncoder().encodeToString(ivAndCiphertext));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt TOTP secret", e);
        }
    }

    @Override
    public byte[] decrypt(EncryptedTotpSecret encrypted) {
        try {
            byte[] ivAndCiphertext = Base64.getDecoder().decode(encrypted.value());
            byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, IV_LENGTH_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(ivAndCiphertext, IV_LENGTH_BYTES, ivAndCiphertext.length);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to decrypt TOTP secret", e);
        }
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
