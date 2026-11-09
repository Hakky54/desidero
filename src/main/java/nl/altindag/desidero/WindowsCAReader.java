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

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Crypt32;
import com.sun.jna.platform.win32.WTypes.LPWSTR;
import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.platform.win32.WinCrypt.CERT_CONTEXT.ByReference;
import com.sun.jna.platform.win32.WinCrypt.CertStoreProviderName;
import com.sun.jna.platform.win32.WinCrypt.HCERTSTORE;
import nl.altindag.desidero.exception.GenericIOException;
import nl.altindag.laleler.CollectorsUtils;
import nl.altindag.sude.Logger;
import nl.altindag.sude.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Reads intermediate CA certificates from the Windows certificate stores
 * using the native Crypt32 API through JNA.
 * <p>
 * Certificates are collected from both the current user and local machine
 * CA stores. They are intended for certificate path building and must not
 * automatically be treated as trust anchors.
 *
 * @author Goldex60
 */
@SuppressWarnings({"SimplifyOptionalCallChains", "CollectionAddAllCanBeReplacedWithConstructor"})
final class WindowsCAReader {

    private static final Logger LOGGER = LoggerFactory.getLogger(WindowsCAReader.class);

    private static final int CRYPT_E_NOT_FOUND = 0x80092004;
    private static final int ERROR_NO_MORE_FILES = 18;
    private static final int ERROR_FILE_NOT_FOUND = 2;
    private static final int ERROR_PATH_NOT_FOUND = 3;
    private static final int CERTIFICATE_ENCODING_TYPE = 0;

    private WindowsCAReader() {
    }

    public static List<X509Certificate> loadCertificates() {
        Set<X509Certificate> certificates = new LinkedHashSet<>();

        List<X509Certificate> currentUserCertificates = readStore(WinCrypt.CERT_SYSTEM_STORE_CURRENT_USER, "CURRENT_USER");
        certificates.addAll(currentUserCertificates);

        List<X509Certificate> localMachineCertificates = readStore(WinCrypt.CERT_SYSTEM_STORE_LOCAL_MACHINE, "LOCAL_MACHINE");
        certificates.addAll(localMachineCertificates);

        return certificates.stream()
                .collect(CollectorsUtils.toUnmodifiableList());
    }

    private static List<X509Certificate> readStore(int location, String locationName) throws GenericIOException {
        Optional<HCERTSTORE> certificateStore = getCertificateStore(location, locationName);
        if (!certificateStore.isPresent()) {
            return Collections.emptyList();
        }

        List<X509Certificate> certificates = new ArrayList<>();
        ByReference context = null;

        try {
            while (true) {
                Pointer previous = context == null ? null : context.getPointer();

                // CertEnumCertificatesInStore frees the previous context. Clear our reference before passing it to the native API to avoid freeing the same context again during cleanup.
                context = null;

                ByReference next = Crypt32.INSTANCE.CertEnumCertificatesInStore(certificateStore.get(), previous);
                int error = next == null ? Native.getLastError() : 0;
                if (next == null) {
                    if (error == CRYPT_E_NOT_FOUND || error == ERROR_NO_MORE_FILES) {
                        break;
                    }

                    throw createException("CertEnumCertificatesInStore", locationName, error);
                }

                context = next;
                X509Certificate certificate = getCertificate(context, locationName);
                certificates.add(certificate);
            }

            return certificates;
        } finally {
            List<String> errorMessages = new ArrayList<>();

            if (context != null) {
                boolean isCertificateContextFreed = Crypt32.INSTANCE.CertFreeCertificateContext(context);
                if (!isCertificateContextFreed) {
                    errorMessages.add(generateErrorMessage("CertFreeCertificateContext", locationName, Native.getLastError()));
                }
            }

            boolean isCertificateStoreClosed = Crypt32.INSTANCE.CertCloseStore(certificateStore.get(), 0);
            if (!isCertificateStoreClosed) {
                errorMessages.add(generateErrorMessage("CertCloseStore", locationName, Native.getLastError()));
            }

            errorMessages.forEach(LOGGER::error);
        }
    }

    private static Optional<HCERTSTORE> getCertificateStore(int location, String locationName) {
        CertStoreProviderName certStoreProviderName = new CertStoreProviderName(WinCrypt.CERT_STORE_PROV_SYSTEM_W);
        int flags = location | WinCrypt.CERT_STORE_READONLY_FLAG | WinCrypt.CERT_STORE_OPEN_EXISTING_FLAG;
        HCERTSTORE store = Crypt32.INSTANCE.CertOpenStore(certStoreProviderName, CERTIFICATE_ENCODING_TYPE, null, flags, new LPWSTR("CA"));

        if (store == null) {
            int errorCode = Native.getLastError();

            if (errorCode == ERROR_FILE_NOT_FOUND || errorCode == ERROR_PATH_NOT_FOUND) {
                return Optional.empty();
            }

            throw createException("CertOpenStore", locationName, errorCode);
        }
        return Optional.of(store);
    }

    private static X509Certificate getCertificate(ByReference context, String locationName) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");

            byte[] encodedCertificate = context.pbCertEncoded.getByteArray(0, context.cbCertEncoded);
            try (InputStream inputStream = new ByteArrayInputStream(encodedCertificate)) {
                return (X509Certificate) factory.generateCertificate(inputStream);
            }
        } catch (CertificateException | IOException e) {
            throw new GenericIOException("Failed to read Windows CA store: " + locationName, e);
        }
    }

    private static GenericIOException createException(String operation, String location, int error) {
        String message = generateErrorMessage(operation, location, error);
        return new GenericIOException(message);
    }

    private static String generateErrorMessage(String operation, String location, int error) {
        return String.format("%s failed for Windows CA/%s (Win32 error: 0x%08X)", operation, location, error);
    }

}
