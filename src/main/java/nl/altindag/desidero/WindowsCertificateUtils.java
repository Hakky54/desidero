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

import nl.altindag.laleler.CollectorsUtils;
import nl.altindag.sude.Logger;
import nl.altindag.sude.LoggerFactory;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static nl.altindag.laleler.CollectorsUtils.toUnmodifiableList;

/**
 * @author Hakan Altindag
 */
public final class WindowsCertificateUtils extends OSCertificateUtils {

    private static final Logger LOGGER  = LoggerFactory.getLogger(WindowsCertificateUtils.class);
    private static WindowsCertificateUtils INSTANCE;
    private static final List<String> WINDOWS_ROOT_KEYSTORE_TYPES = Arrays.asList("Windows-ROOT", "Windows-ROOT-LOCALMACHINE", "Windows-ROOT-CURRENTUSER");
    private static final List<String> WINDOWS_MY_KEYSTORE_TYPES = Arrays.asList("Windows-MY", "Windows-MY-CURRENTUSER", "Windows-MY-LOCALMACHINE");

    private WindowsCertificateUtils() {}

    @Override
    public List<KeyStore> getTrustStores() {
        return Stream.concat(WINDOWS_ROOT_KEYSTORE_TYPES.stream(), WINDOWS_MY_KEYSTORE_TYPES.stream())
                .collect(CollectorsUtils.toListAndThen(this::getTrustStores));
    }

    private List<KeyStore> getTrustStores(List<String> keyStoreTypes) {
        return keyStoreTypes.stream()
                .map(keystoreType -> createKeyStoreIfAvailable(keystoreType, null))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(toUnmodifiableList());
    }

    public List<X509Certificate> getRootCertificates() {
        return getTrustStores(WINDOWS_ROOT_KEYSTORE_TYPES).stream()
                .map(KeyStoreUtils::getCertificates)
                .flatMap(Collection::stream)
                .collect(toUnmodifiableList());
    }

    public List<X509Certificate> getMyCertificates() {
        return getTrustStores(WINDOWS_MY_KEYSTORE_TYPES).stream()
                .map(KeyStoreUtils::getCertificates)
                .flatMap(Collection::stream)
                .collect(toUnmodifiableList());
    }

    public List<X509Certificate> getIntermediateCertificates() {
        if (!isJnaAvailable()) {
            LOGGER.debug("JNA is not on the classpath, skipping getting Windows intermediate CA certificates");
            return Collections.emptyList();
        }

        try {
            return WindowsCAReader.loadCertificates();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load Windows intermediate CA certificates", e);
        }
    }

    private static boolean isJnaAvailable() {
        try {
            Class.forName("com.sun.jna.platform.win32.Crypt32", false, WindowsCertificateUtils.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    public static WindowsCertificateUtils getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new WindowsCertificateUtils();
        }
        return INSTANCE;
    }

}
