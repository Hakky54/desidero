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


import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * @author Hakan Altindag
 */
class WindowsCertificateUtilsShould {

    @Test
    void getInstance() {
        WindowsCertificateUtils instance = WindowsCertificateUtils.getInstance();
        assertThat(instance)
                .isNotNull()
                .hasSameHashCodeAs(WindowsCertificateUtils.getInstance());
    }

    @Test
    void getRootCertificates() {
        X509Certificate certificate = mock(X509Certificate.class);
        KeyStore keyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> mockedKeyStoreUtils = mockStatic(KeyStoreUtils.class)) {
            mockedKeyStoreUtils.when(() -> KeyStoreUtils.createKeyStore(eq("Windows-ROOT"), isNull())).thenReturn(keyStore);
            mockedKeyStoreUtils.when(() -> KeyStoreUtils.getCertificates(keyStore)).thenReturn(Collections.singletonList(certificate));

            assertThat(WindowsCertificateUtils.getInstance().getRootCertificates()).containsExactly(certificate);

            ArgumentCaptor<String> keyStoreTypeCaptor = ArgumentCaptor.forClass(String.class);
            mockedKeyStoreUtils.verify(() -> KeyStoreUtils.createKeyStore(keyStoreTypeCaptor.capture(), isNull()), times(3));
            assertThat(keyStoreTypeCaptor.getAllValues()).containsExactlyInAnyOrder("Windows-ROOT", "Windows-ROOT-LOCALMACHINE", "Windows-ROOT-CURRENTUSER");
        }
    }

    @Test
    void getMyCertificates() {
        X509Certificate certificate = mock(X509Certificate.class);
        KeyStore keyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> mockedKeyStoreUtils = mockStatic(KeyStoreUtils.class)) {
            mockedKeyStoreUtils.when(() -> KeyStoreUtils.createKeyStore(eq("Windows-MY"), isNull())).thenReturn(keyStore);
            mockedKeyStoreUtils.when(() -> KeyStoreUtils.getCertificates(keyStore)).thenReturn(Collections.singletonList(certificate));

            assertThat(WindowsCertificateUtils.getInstance().getMyCertificates()).containsExactly(certificate);

            ArgumentCaptor<String> keyStoreTypeCaptor = ArgumentCaptor.forClass(String.class);
            mockedKeyStoreUtils.verify(() -> KeyStoreUtils.createKeyStore(keyStoreTypeCaptor.capture(), isNull()), times(3));
            assertThat(keyStoreTypeCaptor.getAllValues()).containsExactlyInAnyOrder("Windows-MY", "Windows-MY-CURRENTUSER", "Windows-MY-LOCALMACHINE");
        }
    }

    @Test
    void getRootAndMyCertificatesReturnEmptyListWhenNoKeyStoreIsAvailable() {
        try (MockedStatic<KeyStoreUtils> mockedKeyStoreUtils = mockStatic(KeyStoreUtils.class)) {
            mockedKeyStoreUtils.when(() -> KeyStoreUtils.createKeyStore(any(String.class), any()))
                    .thenThrow(new IllegalStateException("Unavailable"));

            assertThat(WindowsCertificateUtils.getInstance().getRootCertificates()).isEmpty();
            assertThat(WindowsCertificateUtils.getInstance().getMyCertificates()).isEmpty();
        }
    }

    /**
     * Verifies the Windows CA certificate integration without accessing
     * native Windows APIs, allowing the test to run on any operating system.
     */
    @Test
    void getIntermediateCertificatesFromWindowsCAStore() throws Exception {
        X509Certificate intermediate = mock(X509Certificate.class);
        List<X509Certificate> expectedCertificates = Collections.singletonList(intermediate);

        try (MockedStatic<WindowsCAReader> mockedReader = mockStatic(WindowsCAReader.class)) {
            mockedReader.when(WindowsCAReader::loadCertificates)
                    .thenReturn(expectedCertificates);

            List<X509Certificate> certificates = WindowsCertificateUtils.getInstance().getIntermediateCertificates();
            assertThat(certificates).containsExactly(intermediate);
            mockedReader.verify(WindowsCAReader::loadCertificates);
        }
    }

    @Test
    void getIntermediateCertificatesPropagatesReaderFailure() {
        try (MockedStatic<WindowsCAReader> mockedReader = mockStatic(WindowsCAReader.class)) {

            mockedReader.when(WindowsCAReader::loadCertificates)
                    .thenThrow(new IllegalStateException("Native store error"));

            assertThatThrownBy(() ->
                    WindowsCertificateUtils.getInstance()
                            .getIntermediateCertificates())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Failed to load Windows intermediate CA certificates")
                    .hasCauseInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void readNativeWindowsCACertificateStores() {
        assumeTrue(OperatingSystem.get() == OperatingSystem.WINDOWS);

        String originalOsName = System.getProperty("os.name");

        try {
            // Restore the expected Windows capitalization before JNA initialization.
            System.setProperty("os.name", "Windows" + originalOsName.substring(7));
            List<X509Certificate> certificates = WindowsCertificateUtils.getInstance().getIntermediateCertificates();

            assertThat(certificates)
                    .doesNotContainNull()
                    .doesNotHaveDuplicates();
        } finally {
            System.setProperty("os.name", originalOsName);
        }
    }

}
