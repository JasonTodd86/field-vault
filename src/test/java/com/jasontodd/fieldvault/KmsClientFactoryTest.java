package com.jasontodd.fieldvault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

class KmsClientFactoryTest {

    @Test
    void generatesAes256DataKey() {
        try (KmsClient kms = KmsClientFactory.localStack()) {
            String keyId = kms.createKey(r -> r.description("field-vault test")).keyMetadata().keyId();

            GenerateDataKeyResponse resp = kms.generateDataKey(r -> r
                    .keyId(keyId)
                    .keySpec(DataKeySpec.AES_256));

            assertEquals(32, resp.plaintext().asByteArray().length);
            assertTrue(resp.ciphertextBlob().asByteArray().length > 32);
        }
    }
}
