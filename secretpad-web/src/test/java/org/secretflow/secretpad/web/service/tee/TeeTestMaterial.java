/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * 定向测试共用的合成证书与私钥。
 *
 * <p>公开的合成材料，不对应任何真实机构，也不得导入任何运行环境的信任库。
 */
final class TeeTestMaterial {

    /** 合成的自签名测试证书（Base64 DER）。 */
    static final String CERTIFICATE_B64 = "MIIDHzCCAgegAwIBAgIULFzwCQ6wb0nrBoGOoFiqUSEwHXswDQYJKoZIhvcNAQELBQAwHzEdMBsGA1UEAwwUdGVl"
            + "LXRhc2stc2lnbmVyLXRlc3QwHhcNMjYwODMxMTczOTMzWhcNNDYwODI2MTczOTMzWjAfMR0wGwYDVQQDDBR0ZWUt"
            + "dGFzay1zaWduZXItdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALdqOY9UzN9QEeY2cq5eDrO3"
            + "/xSNJOjwugQ0cFjZrhnEYbd2z5Kqk4w/k26RxQWNvvR0eitDTTXTi4GskU8KJGbGnvXNiQRndfOygAlLmffLDVu1"
            + "5oUXg60l6lQjHBWsj5n46UrLLH55tvHXFH1hGYp1JRgyU8M65ctSUnhlfYNOgTeycaUa/ucO+lXRbhjY3rPmOl1R"
            + "XX3GT5S6VH8QPlsBLqndCpQ4BxZod6+xv6P/tCyGhTdUDST862MgKsOnElvems6Okf9mNVwEACUsE51JxeA9dYsR"
            + "OBdny25jTnSVnFWkKlPQ7mNa29VN4vqiCExW37jkUBLdQ/CfOaMH4S8CAwEAAaNTMFEwHQYDVR0OBBYEFOuhx/2I"
            + "pPJPV3Ta8gN3D6hpLLeWMB8GA1UdIwQYMBaAFOuhx/2IpPJPV3Ta8gN3D6hpLLeWMA8GA1UdEwEB/wQFMAMBAf8w"
            + "DQYJKoZIhvcNAQELBQADggEBAFr8QLVMPHysvbNycL0tQBhsxKtH8Rgoye6ZQBQfMjCbUgIiXkl5+QCO8Z5zvcjD"
            + "lyTXJVEv8q+Biw6btpythh5ZDX8Lz8hNnzy6vE2gmoqqQ+nFVzhqmbxmKIn94i/mutnRqL0eSwrLK9PT2v08QMIs"
            + "mHUtlcoqNONhpUEkUaMnMJZHQ4cyQZVblgWHY/BysSB6h1sKH2heQUQOB3SAD9yHhEIpTyGG55E/3kCk+2b8dgdf"
            + "DtMpuRaUBdTrbixZk18OkJwfKtvPsuLMp+cehtcr3pYtfTjXxHZbfsuM9iewWs2DgkDYV/M0ewNzQegvXNcULmi5"
            + "tKAtYUZfX3riass=";

    /** 与上述证书配对的合成私钥（PKCS#8 Base64）。 */
    static final String PRIVATE_KEY_B64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3ajmPVMzfUBHmNnKuXg6zt/8UjSTo8LoENHBY"
            + "2a4ZxGG3ds+SqpOMP5NukcUFjb70dHorQ00104uBrJFPCiRmxp71zYkEZ3XzsoAJS5n3yw1bteaFF4OtJepUIxwV"
            + "rI+Z+OlKyyx+ebbx1xR9YRmKdSUYMlPDOuXLUlJ4ZX2DToE3snGlGv7nDvpV0W4Y2N6z5jpdUV19xk+UulR/ED5b"
            + "AS6p3QqUOAcWaHevsb+j/7QshoU3VA0k/OtjICrDpxJb3prOjpH/ZjVcBAAlLBOdScXgPXWLETgXZ8tuY050lZxV"
            + "pCpT0O5jWtvVTeL6oghMVt+45FAS3UPwnzmjB+EvAgMBAAECggEAA7FcUlHzRAXBLoDnIzKamiy4som69gOuwxnp"
            + "LyjG1Bb7nq2CNWJA0UCQb9f4fwmhEBvuP8O9oLlPJD+8tzotjHIwTiOiwBdzLQJpiIZgpbgNX0zUxNY53PkX9DS2"
            + "wor0YzW7QLnBfhRmRg0+CN41HPAJ3KhavmIHsWXJakok0klwGxzkR51aNwzdR1MntwRrXqKrL089WweNWHgqmJL2"
            + "rvVX2igvgvxIvRiIopjLuBJmSCGe+lCFhQSFw65QQQyXyBh4wlTKWYhF5CwnPr7JQdQdcj++4vhf7BZuhnvIhS8H"
            + "xne2PmSOI5if67j+4wJCixRylSvzDZeyEgHE5y0zAQKBgQDnOyAu+Dve+LYTDECtDpKCQy9ITDuuJ8GESzie6BFM"
            + "mdNnIXUbyeNkH9vv5W7f6O8IqaocT32fO4tg4w6Q/WxBPzbqH1xmo+WtOBFnATUlDcXYxkBfN7ymTHmmxe6s4Rxh"
            + "0cmrjeyv79SMOFlol6LOtzqXVEaZ7CUPmbJJL2j8LwKBgQDLD+BGQ2ZifxDDjWLD6rjA7abHxrIG+kS+3bruMedS"
            + "Y15RxFlAiJmQjh3+yqmjtZwYvARCHZRNmePbXTpz9+0+mHutbKPTaC+kq7995r9YwqmbvU9rW7gedZfJGbMBbMIW"
            + "n4C5JoyLQEELi1Dna8vNKQwNGVU0QGDFIYGSEy0rAQKBgQCR3IU/u80gqSlJuLfvsrqOu0zPQW+AO4niJwUvkFqh"
            + "RIPLkZprDh6H4WT+3m7jhe+LOmOZejdXQ9t3IaPlqEcqnXLJm0DRamAOtcicfnGEzzxXsy+WIPW6vZEbt84IdfRO"
            + "bGTX+C4vCY29aipURRspZQHrxfjHTeRPA/goHGUQdwKBgQCyoLWmuZWwYZyqmY5fT/TUanqDVOu4raGZ0U2mSan2"
            + "1Mjc3v+wgDmuawZB45+VDqZRL9wDGSgjl5NUnk9UQq2lmdd6OI5o40a98gOSylBa0WsIQGFDzLxLtyAd3IiWYUjf"
            + "Q9KljR6nRI+ziwtReIcgY9JhF37XZyZ5Yz8q88mRAQKBgBGCu2vtfpOeik+qr7CZPOeto7boW3Ot3MCoJjYqYEjA"
            + "9jmKZmsmfZuNunUgOSMmAYdkRtUlk9y/JFZDXsbeCyLV3/95pWqsHNN7XPcERNgsqWPJq/hs5bNbTB334E8tGhak"
            + "AUKnlr08vgqP46BBHgenboNaP9mHjgfE01cMQqZZ";

    private TeeTestMaterial() {
    }

    static X509Certificate certificate() throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(CERTIFICATE_B64)));
    }

    static String certificatePem() throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate().getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    static String privateKeyPem() {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(
                        Base64.getDecoder().decode(PRIVATE_KEY_B64))
                + "\n-----END PRIVATE KEY-----\n";
    }

    static PrivateKey privateKey() throws Exception {
        return KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY_B64)));
    }

    /** 把合成材料写成挂载目录的形态：client.crt 与 client.key。 */
    static void writeIdentity(java.nio.file.Path dir) throws Exception {
        java.nio.file.Files.createDirectories(dir);
        java.nio.file.Files.writeString(dir.resolve("client.crt"), certificatePem(), StandardCharsets.UTF_8);
        java.nio.file.Files.writeString(dir.resolve("client.key"), privateKeyPem(), StandardCharsets.UTF_8);
    }
}
