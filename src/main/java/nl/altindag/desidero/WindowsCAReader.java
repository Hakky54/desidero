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
import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.platform.win32.WTypes;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Reads intermediate CA certificates from the Windows certificate stores
 * using the native Crypt32 API through JNA.
 *
 * Certificates are collected from both the current user and local machine
 * CA stores. They are intended for certificate path building and must not
 * automatically be treated as trust anchors.
 *
 * @author Goldex60
 */
final class WindowsCAReader {

    private static final int CRYPT_E_NOT_FOUND = 0x80092004;
    private static final int ERROR_NO_MORE_FILES = 18;
    private static final int ERROR_FILE_NOT_FOUND = 2;
    private static final int ERROR_PATH_NOT_FOUND = 3;

    private WindowsCAReader() {
    }

    public static List<X509Certificate> loadCertificates()
            throws Exception {

        Set<X509Certificate> certificates = new LinkedHashSet<>();

        certificates.addAll(readStore(
                WinCrypt.CERT_SYSTEM_STORE_CURRENT_USER,
                "CURRENT_USER"));

        certificates.addAll(readStore(
                WinCrypt.CERT_SYSTEM_STORE_LOCAL_MACHINE,
                "LOCAL_MACHINE"));

        return new ArrayList<>(certificates);
    }

    private static List<X509Certificate> readStore(
            int location, String locationName) throws Exception {

        WinCrypt.HCERTSTORE store = Crypt32.INSTANCE.CertOpenStore(
                new WinCrypt.CertStoreProviderName(
                        WinCrypt.CERT_STORE_PROV_SYSTEM_W),
                0,
                null,
                location
                        | WinCrypt.CERT_STORE_READONLY_FLAG
                        | WinCrypt.CERT_STORE_OPEN_EXISTING_FLAG,
                new WTypes.LPWSTR("CA")
        );

        if (store == null) {
            int error = Native.getLastError();

            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
                return new ArrayList<>();
            }

            throw nativeError("CertOpenStore", locationName, error);
        }

        List<X509Certificate> certificates = new ArrayList<>();
        WinCrypt.CERT_CONTEXT.ByReference context = null;
        Throwable failure = null;

        try {
            CertificateFactory factory =
                    CertificateFactory.getInstance("X.509");

            while (true) {
                Pointer previous =
                        context == null ? null : context.getPointer();

                // CertEnumCertificatesInStore frees the previous context.
                // Clear our reference before passing it to the native API
                // to avoid freeing the same context again during cleanup.
                context = null;

                WinCrypt.CERT_CONTEXT.ByReference next =
                        Crypt32.INSTANCE.CertEnumCertificatesInStore(
                                store, previous);

                int error = next == null ? Native.getLastError() : 0;

                if (next == null) {
                    if (error == CRYPT_E_NOT_FOUND
                            || error == ERROR_NO_MORE_FILES) {
                        break;
                    }

                    throw nativeError(
                            "CertEnumCertificatesInStore",
                            locationName,
                            error);
                }

                context = next;

                byte[] encoded = context.pbCertEncoded.getByteArray(
                        0, context.cbCertEncoded);

                X509Certificate certificate =
                        (X509Certificate) factory.generateCertificate(
                                new ByteArrayInputStream(encoded));

                certificates.add(certificate);
            }

            return certificates;

        } catch (Exception | Error e) {
            failure = e;
            throw e;

        } finally {
            try {
                if (context != null) {
                    // Release the last certificate context, if still owned.
                    boolean freed =
                            Crypt32.INSTANCE.CertFreeCertificateContext(context);

                    if (!freed) {
                        throw nativeError(
                                "CertFreeCertificateContext",
                                locationName,
                                Native.getLastError());
                    }
                }
            } catch (Exception | Error cleanupError) {
                if (failure != null) {
                    failure.addSuppressed(cleanupError);
                } else {
                    failure = cleanupError;
                }
            } finally {
                // Always close the store, even if context cleanup fails.
                try {
                    boolean closed =
                            Crypt32.INSTANCE.CertCloseStore(store, 0);

                    if (!closed) {
                        throw nativeError(
                                "CertCloseStore",
                                locationName,
                                Native.getLastError());
                    }
                } catch (Exception | Error closeError) {
                    if (failure != null) {
                        failure.addSuppressed(closeError);
                    } else {
                        failure = closeError;
                    }
                }
            }

            if (failure != null) {
                if (failure instanceof Exception) {
                    throw (Exception) failure;
                }
                throw (Error) failure;
            }
        }
    }

    private static IllegalStateException nativeError(
            String operation, String location, int error) {

        return new IllegalStateException(
                operation + " failed for Windows CA/"
                        + location + " (Win32 error: 0x"
                        + String.format("%08X", error) + ")");
    }
}
