package com.jasontodd.fieldvault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

class AesGcmTest {

    private final byte[] key = new byte[32];
    private final byte[] plaintext = "123-45-6789".getBytes(StandardCharsets.UTF_8);

    @Test
    void roundTrip() {
        AesGcm.Sealed sealed = AesGcm.encrypt(key, plaintext);
        assertArrayEquals(plaintext, AesGcm.decrypt(key, sealed.iv(), sealed.ciphertext()));
    }

    @Test
    void ciphertextDoesNotContainPlaintext() {
        AesGcm.Sealed sealed = AesGcm.encrypt(key, plaintext);
        assertFalse(Arrays.equals(plaintext, sealed.ciphertext()));
    }

    @Test
    void sameInputGivesDifferentCiphertext() {
        AesGcm.Sealed a = AesGcm.encrypt(key, plaintext);
        AesGcm.Sealed b = AesGcm.encrypt(key, plaintext);
        assertFalse(Arrays.equals(a.ciphertext(), b.ciphertext()));
    }

    @Test
    void tamperedCiphertextIsRejected() {
        AesGcm.Sealed sealed = AesGcm.encrypt(key, plaintext);
        sealed.ciphertext()[0] ^= 1;
        assertThrows(IllegalStateException.class,
                () -> AesGcm.decrypt(key, sealed.iv(), sealed.ciphertext()));
    }
}
