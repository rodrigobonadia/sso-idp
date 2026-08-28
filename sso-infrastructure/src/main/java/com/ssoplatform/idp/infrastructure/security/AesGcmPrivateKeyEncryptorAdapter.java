package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.PrivateKeyEncryptor;
import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;
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
 * Implements the {@link PrivateKeyEncryptor} output port with AES-256-GCM, keyed from {@code
 * app.signing-key.encryption-secret} (environment variable {@code SIGNING_KEY_ENCRYPTION_SECRET})
 * - per {@code architecture_decisions.md}, decision (j): the master secret is never stored
 * alongside the database itself, so a database leak alone cannot expose any tenant's private
 * signing key.
 *
 * <p>The configured secret is not required to already be a 256-bit key: it is passed through
 * SHA-256 to deterministically derive one, regardless of the secret's own length or format - this
 * keeps the operational requirement simple ("set a strong secret string") rather than requiring an
 * operator to generate and manage a correctly-sized, correctly-encoded key by hand.
 *
 * <p>Each {@link #encrypt} call generates a fresh random 96-bit IV (the size GCM is designed for)
 * via {@link SecureRandom} and prepends it to the ciphertext before Base64-encoding the result, so
 * the same private key never produces the same stored value twice and no IV needs to be persisted
 * as a separate column.
 */
@Component
public class AesGcmPrivateKeyEncryptorAdapter implements PrivateKeyEncryptor {

    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private final SecretKeySpec secretKey;

    public AesGcmPrivateKeyEncryptorAdapter(@Value("${app.signing-key.encryption-secret}") String encryptionSecret) {
        if (encryptionSecret == null || encryptionSecret.isBlank()) {
            throw new IllegalStateException(
                    "app.signing-key.encryption-secret (SIGNING_KEY_ENCRYPTION_SECRET) must not be blank");
        }
        this.secretKey = new SecretKeySpec(sha256(encryptionSecret), KEY_ALGORITHM);
    }

    @Override
    public EncryptedPrivateKeyMaterial encrypt(byte[] privateKeyDer) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] ciphertext = cipher.doFinal(privateKeyDer);

            byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
            System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

            return EncryptedPrivateKeyMaterial.of(Base64.getEncoder().encodeToString(ivAndCiphertext));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt private key material", e);
        }
    }

    @Override
    public byte[] decrypt(EncryptedPrivateKeyMaterial encrypted) {
        try {
            byte[] ivAndCiphertext = Base64.getDecoder().decode(encrypted.value());
            byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, IV_LENGTH_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(ivAndCiphertext, IV_LENGTH_BYTES, ivAndCiphertext.length);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to decrypt private key material", e);
        }
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available on every conforming JVM (JLS platform
            // requirement), so this can only ever indicate a broken JVM installation.
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
