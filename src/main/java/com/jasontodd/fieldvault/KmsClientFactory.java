package com.jasontodd.fieldvault;

import java.net.URI;
import java.time.Duration;
// AWS software development kit.
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
// software.amazon.awssdk:kms from the pom.xml is the wrappper of KMS only
/* 
KMS is an HTTPS service. 
The SDK gives you Java methods like kms.generateDataKey(...), 
and it handles signing, retries, timeouts, and parsing responses.
*/

public final class KmsClientFactory {

    private KmsClientFactory() {}

    public static KmsClient localStack() {
        return KmsClient.builder()
                .endpointOverride(URI.create("http://localhost:4566"))
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .apiCallAttemptTimeout(Duration.ofSeconds(2))
                        .apiCallTimeout(Duration.ofSeconds(5))
                        .build())
                .build();
    }
}
