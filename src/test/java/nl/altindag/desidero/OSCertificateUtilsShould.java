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

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
class OSCertificateUtilsShould {

    private static final String ORIGINAL_OS_NAME = System.getProperty("os.name");
    private final OSCertificateUtils oscertificateUtils = new OSCertificateUtils() {
        @Override
        List<KeyStore> getTrustStores() {
            return Collections.emptyList();
        }
    };

    @Test
    void loadCertificateIgnoresInvalidFiles() throws IOException {
        Path path = IOTestUtils.copyFileToHomeDirectory("pem/", "invalid.pem");
        List<Certificate> certificates = oscertificateUtils.loadCertificate(path);
        assertThat(certificates).isEmpty();
        Files.delete(path);
    }

    @Test
    void loadCertificateReadsValidFiles() throws IOException {
        Path path = IOTestUtils.copyFileToHomeDirectory("pem/", "badssl-certificate.pem");
        List<Certificate> certificates = oscertificateUtils.loadCertificate(path);
        assertThat(certificates).isNotEmpty();
        Files.delete(path);
    }

    @Test
    void createKeyStoreIfAvailableReturnsEmptyForNonExistingKeyStoreType() {
        OSCertificateUtils osCertificateUtils = new OSCertificateUtils() {
            @Override
            List<KeyStore> getTrustStores() {
                return Collections.emptyList();
            }
        };

        Optional<KeyStore> bananaKeyStore = osCertificateUtils.createKeyStoreIfAvailable("Banana", null);
        assertThat(bananaKeyStore).isEmpty();
    }

    @Test
    void createKeyStoreIfAvailableReturnsFilledKeyStore() {
        KeyStore bananaKeyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> mockedStatic = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName()) && method.getParameterCount() == 2 && "Banana".equals(invocation.getArgument(0))) {
                return bananaKeyStore;
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            OSCertificateUtils osCertificateUtils = new OSCertificateUtils() {
                @Override
                List<KeyStore> getTrustStores() {
                    return Collections.emptyList();
                }
            };

            Optional<KeyStore> keyStore = osCertificateUtils.createKeyStoreIfAvailable("Banana", null);
            assertThat(keyStore).isPresent();
        }
    }

    @Test
    void createKeyStoreIfAvailableReturnsFilledKeyStoreWithoutLoggingIfDebugIsDisabled() {
        KeyStore bananaKeyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> mockedStatic = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName()) && method.getParameterCount() == 2 && "Banana".equals(invocation.getArgument(0))) {
                return bananaKeyStore;
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            OSCertificateUtils osCertificateUtils = new OSCertificateUtils() {
                @Override
                List<KeyStore> getTrustStores() {
                    return Collections.emptyList();
                }
            };

            Optional<KeyStore> keyStore = osCertificateUtils.createKeyStoreIfAvailable("Banana", null);
            assertThat(keyStore).isPresent();
        }
    }

    @Test
    void loadWindowsSystemKeyStore() {
        System.setProperty("os.name", "windows");
        KeyStore windowsRootKeyStore = mock(KeyStore.class);
        KeyStore windowsMyKeyStore = mock(KeyStore.class);
        KeyStore windowsMyCurrentUserKeyStore = mock(KeyStore.class);
        KeyStore windowsMyLocalmachineKeyStore = mock(KeyStore.class);
        KeyStore windowsRootCurrentUserKeyStore = mock(KeyStore.class);
        KeyStore windowsRootLocalmachineKeyStore = mock(KeyStore.class);

        WindowsCertificateUtils windowsCertificateUtils = spy(WindowsCertificateUtils.class);
        when(windowsCertificateUtils.createKeyStoreIfAvailable("Windows-ROOT", null)).thenReturn(Optional.of(windowsRootKeyStore));
        when(windowsCertificateUtils.createKeyStoreIfAvailable("Windows-MY", null)).thenReturn(Optional.of(windowsMyKeyStore));
        when(windowsCertificateUtils.createKeyStoreIfAvailable("Windows-MY-CURRENTUSER", null)).thenReturn(Optional.of(windowsMyCurrentUserKeyStore));
        when(windowsCertificateUtils.createKeyStoreIfAvailable("Windows-MY-LOCALMACHINE", null)).thenReturn(Optional.of(windowsMyLocalmachineKeyStore));
        when(windowsCertificateUtils.createKeyStoreIfAvailable("Windows-ROOT-LOCALMACHINE", null)).thenReturn(Optional.of(windowsRootLocalmachineKeyStore));
        when(windowsCertificateUtils.createKeyStoreIfAvailable("Windows-ROOT-CURRENTUSER", null)).thenReturn(Optional.of(windowsRootCurrentUserKeyStore));

        OperatingSystem mockedOperatingSystem = spy(OperatingSystem.WINDOWS);
        when(mockedOperatingSystem.getOsCertificateUtils()).thenReturn(Optional.of(windowsCertificateUtils));

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                return invocation.callRealMethod();
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.getMock();
            }
        }); MockedStatic<WindowsCertificateUtils> osCertificateUtilsMock = mockStatic(WindowsCertificateUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getInstance".equals(method.getName())) {
                return windowsCertificateUtils;
            } else {
                return invocation.callRealMethod();
            }
        }); MockedStatic<OperatingSystem> operatingSystemEnumMock = mockStatic(OperatingSystem.class, invocation -> {
            Method method = invocation.getMethod();
            if ("get".equals(method.getName())) {
                return mockedOperatingSystem;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            List<KeyStore> keyStores = OperatingSystem.get().getTrustStores();
            assertThat(keyStores).containsExactlyInAnyOrder(windowsRootKeyStore, windowsMyKeyStore, windowsMyCurrentUserKeyStore, windowsMyLocalmachineKeyStore, windowsRootCurrentUserKeyStore, windowsRootLocalmachineKeyStore);
        } finally {
            resetOsName();
        }
    }

    @Test
    void loadAndroidSystemKeyStoreWithAndroidSystemProperty() {
        System.setProperty("os.name", "Linux");

        Map<String, String> androidProperties = new HashMap<>();
        androidProperties.put("java.vendor", "The Android Project");
        androidProperties.put("java.vm.vendor", "The Android Project");
        androidProperties.put("java.runtime.name", "Android Runtime");

        androidProperties.forEach((key, value) -> {
            System.setProperty(key, value);

            KeyStore androidCAStore = mock(KeyStore.class);
            AndroidCertificateUtils androidCertificateUtils = spy(AndroidCertificateUtils.class);
            when(androidCertificateUtils.createKeyStoreIfAvailable("AndroidCAStore", null)).thenReturn(Optional.of(androidCAStore));
            OperatingSystem mockedOperatingSystem = spy(OperatingSystem.ANDROID);
            when(mockedOperatingSystem.getOsCertificateUtils()).thenReturn(Optional.of(androidCertificateUtils));

            try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
                Method method = invocation.getMethod();
                if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                    return invocation.callRealMethod();
                } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                    return 2;
                } else {
                    return invocation.getMock();
                }
            }); MockedStatic<AndroidCertificateUtils> osCertificateUtilsMock = mockStatic(AndroidCertificateUtils.class, invocation -> {
                Method method = invocation.getMethod();
                if ("getInstance".equals(method.getName())) {
                    return androidCertificateUtils;
                } else {
                    return invocation.callRealMethod();
                }
            }); MockedStatic<OperatingSystem> operatingSystemEnumMock = mockStatic(OperatingSystem.class, invocation -> {
                Method method = invocation.getMethod();
                if ("get".equals(method.getName())) {
                    return mockedOperatingSystem;
                } else {
                    return invocation.callRealMethod();
                }
            })) {
                List<KeyStore> keyStores = OperatingSystem.get().getTrustStores();
                assertThat(keyStores).containsExactly(androidCAStore);
            } finally {
                System.clearProperty(key);
            }
        });

        resetOsName();
    }

        @Test
    void notLoadAndroidSystemKeyStoreWhenAdditionalAndroidPropertiesAreMissing() {
        System.setProperty("os.name", "Linux");
        System.clearProperty("java.vendor");
        System.clearProperty("java.vm.vendor");
        System.clearProperty("java.runtime.name");

        LinuxCertificateUtils linuxCertificateUtils = mock(LinuxCertificateUtils.class);

        try (MockedStatic<LinuxCertificateUtils> linuxCertificateUtilsMockedStatic = mockStatic(LinuxCertificateUtils.class, invocationOnMock -> linuxCertificateUtils);
             MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class)) {
            OperatingSystem.get().getTrustStores();
            keyStoreUtilsMock.verify(() -> KeyStoreUtils.createKeyStore("AndroidCAStore", null), times(0));
        } finally {
            resetOsName();
        }
    }

    @Test
    void loadLinuxSystemKeyStoreReturns() {
        System.setProperty("os.name", "linux");

        KeyStore systemTrustStore = mock(KeyStore.class);

        LinuxCertificateUtils linuxCertificateUtils = mock(LinuxCertificateUtils.class);
        when(linuxCertificateUtils.getTrustStores()).thenReturn(Collections.singletonList(systemTrustStore));
        OperatingSystem mockedOperatingSystem = spy(OperatingSystem.LINUX);
        when(mockedOperatingSystem.getOsCertificateUtils()).thenReturn(Optional.of(linuxCertificateUtils));

        try (MockedStatic<LinuxCertificateUtils> linuxCertificateUtilsMockedStatic = mockStatic(LinuxCertificateUtils.class, invocationOnMock -> linuxCertificateUtils);
             MockedStatic<KeyStoreUtils> keyStoreUtilsMockedStatic = mockStatic(KeyStoreUtils.class, invocation -> {
                 Method method = invocation.getMethod();
                 if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                     return invocation.callRealMethod();
                 } else if ("createTrustStore".equals(method.getName()) && method.getParameterCount() == 1 && method.getParameters()[0].getType().equals(List.class)) {
                     return systemTrustStore;
                 } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                     return 2;
                 } else {
                     return invocation.getMock();
                 }
             }); MockedStatic<OperatingSystem> operatingSystemEnumMock = mockStatic(OperatingSystem.class, invocation -> {
            Method method = invocation.getMethod();
            if ("get".equals(method.getName())) {
                return mockedOperatingSystem;
            } else {
                return invocation.callRealMethod();
            }
        })) {

            List<KeyStore> keyStores = OperatingSystem.get().getTrustStores();
            assertThat(keyStores).containsExactly(systemTrustStore);
            assertThat(linuxCertificateUtils.getTrustStores()).containsExactly(systemTrustStore);
        }

        resetOsName();
    }

    @Test
    void notLoadSystemKeyStoreForUnknownOs() {
        System.setProperty("os.name", "Banana OS");
        LogCaptor logCaptor = LogCaptor.forClass(OperatingSystem.class);

        List<KeyStore> keyStores = OperatingSystem.get().getTrustStores();

        assertThat(keyStores).isEmpty();
        assertThat(logCaptor.getWarnLogs()).contains("No system KeyStores available for [banana os]");

        logCaptor.close();
        resetOsName();
    }

    private void resetOsName() {
        System.setProperty("os.name", ORIGINAL_OS_NAME);
    }

}
