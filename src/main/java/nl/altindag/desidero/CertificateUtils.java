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

import nl.altindag.desidero.exception.GenericIOException;
import nl.altindag.laleler.IOUtils;

import javax.security.auth.x500.X500Principal;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static nl.altindag.laleler.CollectorsUtils.toUnmodifiableList;

/**
 * @author Hakan Altindag
 */
final class CertificateUtils {

    private static final String CERTIFICATE_TYPE = "X.509";
    private static final String P7B_HEADER = "-----BEGIN PKCS7-----";
    private static final String P7B_FOOTER = "-----END PKCS7-----";
    private static final String PEM_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_FOOTER = "-----END CERTIFICATE-----";
    private static final Pattern PEM_PATTERN = Pattern.compile(PEM_HEADER + "(.*?)" + PEM_FOOTER, Pattern.DOTALL);
    private static final Pattern P7B_PATTERN = Pattern.compile(P7B_HEADER + "(.*?)" + P7B_FOOTER, Pattern.DOTALL);
    private static final String EMPTY = "";

    private CertificateUtils() {}

    static <T extends Certificate> String generateAlias(T certificate) {
        if (certificate instanceof X509Certificate) {
            return ((X509Certificate) certificate)
                    .getSubjectX500Principal()
                    .getName(X500Principal.CANONICAL)
                    .replace(" ", "-")
                    .replace(",", "_")
                    .replace("'", "")
                    .replaceAll("[.*\\\\/:()#]+", "")
                    .replaceAll("(-)\\1+", "$1");
        } else {
            return UUID.randomUUID().toString().toLowerCase(Locale.US);
        }
    }

    /**
     * Loads certificates from the filesystem and maps it into a list of {@link Certificate}.
     * <br>
     * Supported input format: PEM, P7B and DER
     */
    static List<Certificate> loadCertificate(Path path) {
        try {
            return loadCertificate(certificatePath -> {
                try {
                    return Files.newInputStream(certificatePath, StandardOpenOption.READ);
                } catch (IOException exception) {
                    throw new GenericIOException(exception);
                }
            }, new Path[]{path});
        } catch (Exception e) {
            // Ignore exception and skip trying to parse the file as it is most likely
            // not a (supported) certificate at all. It might be a regular text file maybe containing random text?
            return Collections.emptyList();
        }
    }

    private static <T> List<Certificate> loadCertificate(Function<T, InputStream> resourceMapper, T[] resources) {
        List<Certificate> certificates = new ArrayList<>();
        for (T resource : resources) {
            try (InputStream certificateStream = resourceMapper.apply(resource)) {
                certificates.addAll(parseCertificate(certificateStream));
            } catch (Exception e) {
                throw new GenericIOException(e);
            }
        }

        return Collections.unmodifiableList(certificates);
    }

    /**
     * Tries to map the InputStream to a list of {@link Certificate}.
     * It assumes that the content of the InputStream is either PEM, P7B or DER.
     * The InputStream will copied into an OutputStream so it can be read multiple times.
     */
    private static List<Certificate> parseCertificate(InputStream certificateStream) {
        List<Certificate> certificates;
        byte[] certificateData = IOUtils.copyToByteArray(certificateStream, GenericIOException::new);
        String certificateContent = new String(certificateData, StandardCharsets.UTF_8);

        if (isPemFormatted(certificateContent)) {
            certificates = parsePemCertificate(certificateContent);
        } else if(isP7bFormatted(certificateContent)) {
            certificates = parseP7bCertificate(certificateContent);
        } else {
            certificates = parseDerCertificate(new ByteArrayInputStream(certificateData));
        }

        return certificates;
    }

    private static boolean isPemFormatted(String certificateContent) {
        return PEM_PATTERN.matcher(certificateContent).find();
    }

    private static boolean isP7bFormatted(String certificateContent) {
        return P7B_PATTERN.matcher(certificateContent).find();
    }

    /**
     * Parses PEM formatted certificates containing a
     * header as -----BEGIN CERTIFICATE----- and footer as -----END CERTIFICATE-----
     * or header as -----BEGIN PKCS7----- and footer as -----END PKCS7-----
     * with a base64 encoded data between the header and footer.
     */
    static List<Certificate> parsePemCertificate(String certificateContent) {
        Matcher pemMatcher = PEM_PATTERN.matcher(certificateContent);
        return parseCertificate(pemMatcher);
    }

    /**
     * Parses P7B formatted certificates containing a
     * header as -----BEGIN PKCS7----- and footer as -----END PKCS7-----
     * with a base64 encoded data between the header and footer.
     */
    static List<Certificate> parseP7bCertificate(String certificateContent) {
        Matcher p7bMatcher = P7B_PATTERN.matcher(certificateContent);
        return parseCertificate(p7bMatcher);
    }

    private static List<Certificate> parseCertificate(Matcher certificateMatcher) {
        List<Certificate> certificates = new ArrayList<>();
        while (certificateMatcher.find()) {
            String certificate = certificateMatcher.group(1);
            String sanitizedCertificate = certificate.replaceAll("[\\n|\\r]+", EMPTY).trim();
            byte[] decodedCertificate = Base64.getDecoder().decode(sanitizedCertificate);
            ByteArrayInputStream certificateAsInputStream = new ByteArrayInputStream(decodedCertificate);
            List<Certificate> parsedCertificates = CertificateUtils.parseDerCertificate(certificateAsInputStream);
            certificates.addAll(parsedCertificates);
            IOUtils.closeSilently(certificateAsInputStream);
        }

        return Collections.unmodifiableList(certificates);
    }

    static List<Certificate> parseDerCertificate(InputStream certificateStream) {
        try(BufferedInputStream bufferedCertificateStream = new BufferedInputStream(certificateStream)) {
            return CertificateFactory.getInstance(CERTIFICATE_TYPE)
                    .generateCertificates(bufferedCertificateStream).stream()
                    .collect(toUnmodifiableList());
        } catch (CertificateException | IOException e) {
            return Collections.emptyList();
        }
    }

}
