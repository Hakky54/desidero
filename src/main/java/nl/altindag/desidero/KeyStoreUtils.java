/*
 * Copyright 2026 Thunderberry.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.desidero;

import nl.altindag.desidero.exception.GenericKeyStoreException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static nl.altindag.laleler.ValidationUtils.requireNotEmpty;

/**
 * @author Hakan Altindag
 */
final class KeyStoreUtils {

    private static final String DUMMY_PASSWORD = "dummy-password";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String EMPTY_CERTIFICATES_EXCEPTION = "Could not create TrustStore because certificate is absent";

    private KeyStoreUtils() {}

    static <T extends Certificate> KeyStore createTrustStore(List<T> certificates) {
        try {
            KeyStore trustStore = createKeyStore();
            for (T certificate : requireNotEmpty(certificates, EMPTY_CERTIFICATES_EXCEPTION)) {
                String alias = CertificateUtils.generateAlias(certificate);
                boolean shouldAddCertificate = true;

                if (trustStore.containsAlias(alias)) {
                    for (int number = 0; number <= 1000; number++) {
                        String mayBeUniqueAlias = alias + "-" + number;
                        if (!trustStore.containsAlias(mayBeUniqueAlias)) {
                            alias = mayBeUniqueAlias;
                            shouldAddCertificate = true;
                            break;
                        } else {
                            shouldAddCertificate = false;
                        }
                    }
                }

                if (shouldAddCertificate) {
                    trustStore.setCertificateEntry(alias, certificate);
                }
            }
            return trustStore;
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    static KeyStore createKeyStore() {
        return createKeyStore(DUMMY_PASSWORD.toCharArray());
    }

    static KeyStore createKeyStore(char[] keyStorePassword) {
        return createKeyStore(KEYSTORE_TYPE, keyStorePassword);
    }

    static KeyStore createKeyStore(String keyStoreType, char[] keyStorePassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, keyStorePassword);
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static int countAmountOfTrustMaterial(KeyStore keyStore) {
        return amountOfSpecifiedMaterial(keyStore, KeyStore::isCertificateEntry, Integer.MAX_VALUE);
    }

    private static int amountOfSpecifiedMaterial(KeyStore keyStore,
                                                 KeyStoreBiPredicate<KeyStore, String> predicate,
                                                 int upperBoundaryForMaterialCounter) {

        try {
            int materialCounter = 0;

            List<String> aliases = getAliases(keyStore);
            for (String alias : aliases) {
                if (materialCounter < upperBoundaryForMaterialCounter && predicate.test(keyStore, alias)) {
                    materialCounter++;
                }
            }
            return materialCounter;
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static List<String> getAliases(KeyStore keyStore) {
        try {
            List<String> destinationAliases = new ArrayList<>();
            Enumeration<String> sourceAliases = keyStore.aliases();
            while (sourceAliases.hasMoreElements()) {
                String alias = sourceAliases.nextElement();
                destinationAliases.add(alias);
            }

            return Collections.unmodifiableList(destinationAliases);
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    private interface KeyStoreBiPredicate<T extends KeyStore, U> {
        boolean test(T t, U u) throws KeyStoreException;
    }

}
