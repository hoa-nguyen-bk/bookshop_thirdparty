package com.cybersoft.thirdparty.utils;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class SignatureUtils {

        private SignatureUtils() {}

        // =========================================================
        // ============== EXISTING LOAD METHODS ====================
        // =========================================================

        public static PrivateKey loadPrivateKeyPem(String pem) throws Exception {
            return loadPrivateKeyPem(pem, null);
        }

        public static PrivateKey loadPrivateKeyPem(String pem, String algorithm) throws Exception {
            if (pem == null) throw new IllegalArgumentException("pem == null");
            String normalized = pem
                    .replaceAll("-----BEGIN ([A-Z ]+)-----", "")
                    .replaceAll("-----END ([A-Z ]+)-----", "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(normalized);

            try {
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                KeyFactory kf = (algorithm == null)
                        ? guessKeyFactory(spec.getEncoded())
                        : KeyFactory.getInstance(algorithm);
                return kf.generatePrivate(spec);
            } catch (Exception e) {
                // try BC fallback
            }

            try {
                if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                    Security.addProvider(new BouncyCastleProvider());
                }

                try (Reader rdr = new StringReader(pem);
                     PEMParser pemParser = new PEMParser(rdr)) {
                    Object obj = pemParser.readObject();
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

                    if (obj instanceof PEMKeyPair) {
                        PrivateKeyInfo pki = ((PEMKeyPair) obj).getPrivateKeyInfo();
                        return converter.getPrivateKey(pki);
                    }
                    if (obj instanceof PrivateKeyInfo) {
                        return converter.getPrivateKey((PrivateKeyInfo) obj);
                    }
                }
            } catch (Exception ex) {
                throw new IllegalArgumentException(
                        "Failed to parse private key (maybe PKCS#1). Try converting with OpenSSL or add BouncyCastle.",
                        ex);
            }

            throw new IllegalArgumentException("Unsupported private key format or algorithm.");
        }

        public static PublicKey loadPublicKeyPem(String pem) throws Exception {
            if (pem == null) throw new IllegalArgumentException("pem == null");
            String normalized = pem
                    .replaceAll("-----BEGIN ([A-Z ]+)-----", "")
                    .replaceAll("-----END ([A-Z ]+)-----", "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(normalized);

            try {
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                KeyFactory kf = guessKeyFactory(spec.getEncoded());
                return kf.generatePublic(spec);
            } catch (Exception e) {
                // fallback BC
            }

            try {
                if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                    Security.addProvider(new BouncyCastleProvider());
                }
                try (Reader rdr = new StringReader(pem);
                     PEMParser pemParser = new PEMParser(rdr)) {
                    Object obj = pemParser.readObject();
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                    if (obj instanceof SubjectPublicKeyInfo) {
                        return converter.getPublicKey((SubjectPublicKeyInfo) obj);
                    }
                }
            } catch (Exception ex) {
                throw new IllegalArgumentException("Failed to parse public key.", ex);
            }

            throw new IllegalArgumentException("Unsupported public key format");
        }

        // =========================================================
        // ============== NEW: LOAD FROM RESOURCES =================
        // =========================================================

        /**
         * Load a private key PEM file from classpath (src/main/resources)
         * Example: SignatureUtils.loadPrivateKeyFromResource("keys/private_key.pem", "RSA");
         */
        public static PrivateKey loadPrivateKeyFromResource(String resourcePath, String algorithm) throws Exception {
            String pem = readResourceAsString(resourcePath);
            return loadPrivateKeyPem(pem, algorithm);
        }

        /**
         * Load a public key PEM file from classpath (src/main/resources)
         * Example: SignatureUtils.loadPublicKeyFromResource("keys/public_key.pem", "RSA");
         */
        public static PublicKey loadPublicKeyFromResource(String resourcePath, String algorithm) throws Exception {
            String pem = readResourceAsString(resourcePath);
            return loadPublicKeyPem(pem);
        }

        // Helper: read file from resources into String (UTF-8)
        private static String readResourceAsString(String resourcePath) throws IOException {
            InputStream is = SignatureUtils.class.getClassLoader().getResourceAsStream(resourcePath);
            if (is == null) {
                throw new FileNotFoundException("Resource not found: " + resourcePath);
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                return sb.toString();
            }
        }

        // =========================================================
        // ============== EXISTING SIGN / VERIFY ===================
        // =========================================================

        public static String signWithPrivateKey(PrivateKey privateKey, byte[] data, String algorithmSignature) throws Exception {
            if (privateKey == null) throw new IllegalArgumentException("privateKey == null");
            if (algorithmSignature == null || algorithmSignature.isEmpty())
                algorithmSignature = guessSignatureAlgorithm(privateKey);
            Signature sig = Signature.getInstance(algorithmSignature);
            sig.initSign(privateKey);
            sig.update(data);
            byte[] signed = sig.sign();
            return Base64.getEncoder().encodeToString(signed);
        }

        public static boolean verifyWithPublicKey(PublicKey publicKey, byte[] data, byte[] signatureBytes, String algorithmSignature) throws Exception {
            if (publicKey == null) throw new IllegalArgumentException("publicKey == null");
            if (algorithmSignature == null || algorithmSignature.isEmpty())
                algorithmSignature = guessSignatureAlgorithm(publicKey);
            Signature sig = Signature.getInstance(algorithmSignature);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signatureBytes);
        }

        public static boolean verifyWithPublicKeyBase64(PublicKey publicKey, byte[] data, String signatureBase64, String algorithmSignature) throws Exception {
            byte[] sigBytes = Base64.getDecoder().decode(signatureBase64);
            return verifyWithPublicKey(publicKey, data, sigBytes, algorithmSignature);
        }

        public static String hmacSha256Base64(String secret, byte[] data) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getEncoder().encodeToString(mac.doFinal(data));
        }

        public static byte[] sha256(byte[] data) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        }

        public static boolean constantTimeEquals(byte[] a, byte[] b) {
            if (a == null || b == null) return false;
            if (a.length != b.length) return false;
            int result = 0;
            for (int i = 0; i < a.length; i++) {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        private static KeyFactory guessKeyFactory(byte[] encoded) throws Exception {
            try { return KeyFactory.getInstance("RSA"); } catch (Exception ignored) {}
            try { return KeyFactory.getInstance("EC"); } catch (Exception ignored) {}
            return KeyFactory.getInstance("DSA");
        }

        private static String guessSignatureAlgorithm(Key key) {
            if (key instanceof RSAPrivateKey || key instanceof RSAPublicKey) return "SHA256withRSA";
            if ("EC".equalsIgnoreCase(key.getAlgorithm())) return "SHA256withECDSA";
            if ("DSA".equalsIgnoreCase(key.getAlgorithm())) return "SHA256withDSA";
            return "SHA256withRSA";
        }
    }

