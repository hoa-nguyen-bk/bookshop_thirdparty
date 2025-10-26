package com.cybersoft.thirdparty.utils;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
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

        // ===================== AES-GCM (symmetric) =====================

        /**
         * Generate a random AES key (in bytes) with given keySizeBits (128 or 256).
         */
        public static byte[] generateAesKey(int keySizeBits) throws NoSuchAlgorithmException {
            if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256) {
                throw new IllegalArgumentException("Unsupported AES key size: " + keySizeBits);
            }
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(keySizeBits, SecureRandom.getInstanceStrong());
            SecretKey sk = kg.generateKey();
            return sk.getEncoded();
        }

        /**
         * Encrypt plaintext with AES-GCM. Returns a Base64 string containing iv:ciphertext (iv and ciphertext are Base64, separated by '.').
         * iv length is 12 bytes (recommended).
         */
        public static String encryptAesGcm(byte[] aesKey, byte[] plaintext, byte[] associatedData) throws Exception {
            byte[] iv = new byte[12];
            SecureRandom.getInstanceStrong().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit auth tag
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            if (associatedData != null) cipher.updateAAD(associatedData);

            byte[] ciphertext = cipher.doFinal(plaintext);

            String ivB64 = Base64.getEncoder().encodeToString(iv);
            String ctB64 = Base64.getEncoder().encodeToString(ciphertext);
            return ivB64 + "." + ctB64;
        }

        /**
         * Decrypt AES-GCM output produced by encryptAesGcm.
         * input format: ivBase64.ciphertextBase64
         */
        public static byte[] decryptAesGcm(byte[] aesKey, String ivAndCiphertext, byte[] associatedData) throws Exception {
            String[] parts = ivAndCiphertext.split("\\.", 2);
            if (parts.length != 2) throw new IllegalArgumentException("Invalid AES-GCM input format");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] ciphertext = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            if (associatedData != null) cipher.updateAAD(associatedData);
            return cipher.doFinal(ciphertext);
        }

        // ===================== RSA OAEP (asymmetric) =====================

        /**
         * Encrypt small data (e.g., AES key) with RSA OAEP (SHA-256).
         */
        public static byte[] rsaEncryptOaep(PublicKey publicKey, byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            // explicit OAEP params (optional but clearer)
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    new MGF1ParameterSpec("SHA-256"),
                    PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // Some JDKs accept cipher.init with OAEPParameterSpec; if needed: cipher = Cipher.getInstance(..., "BC") after adding BC
            return cipher.doFinal(data);
        }

        /**
         * Decrypt RSA OAEP encrypted data with private key.
         */
        public static byte[] rsaDecryptOaep(PrivateKey privateKey, byte[] encrypted) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encrypted);
        }

        // ===================== HYBRID (RSA + AES-GCM) =====================

        /**
         * Hybrid encrypt: generate AES key, encrypt plaintext with AES-GCM, encrypt AES key with RSA-OAEP.
         * Returns a String: "hybrid:<encKeyBase64>.<ivBase64>.<ciphertextBase64>"
         *
         * Note: RSA can only encrypt small data (size < keySizeBytes - overhead). We only encrypt the AES key.
         */
        public static String hybridEncrypt(PublicKey rsaPublicKey, byte[] plaintext, byte[] associatedData) throws Exception {
            // 1) generate AES key (256 bits recommended)
            byte[] aesKey;
            try {
                aesKey = generateAesKey(256);
            } catch (NoSuchAlgorithmException e) {
                // fallback to 128 if 256 not allowed
                aesKey = generateAesKey(128);
            }

            // 2) encrypt plaintext with AES-GCM
            String ivAndCiphertext = encryptAesGcm(aesKey, plaintext, associatedData); // returns iv.ct

            // 3) encrypt AES key with RSA-OAEP
            byte[] encKey = rsaEncryptOaep(rsaPublicKey, aesKey);

            String encKeyB64 = Base64.getEncoder().encodeToString(encKey);
            // ivAndCiphertext already in form ivB64.ctB64
            return "hybrid:" + encKeyB64 + "." + ivAndCiphertext;
        }

        /**
         * Hybrid decrypt: input the hybrid string returned by hybridEncrypt.
         * Returns decrypted plaintext bytes.
         */
        public static byte[] hybridDecrypt(PrivateKey rsaPrivateKey, String hybridInput, byte[] associatedData) throws Exception {
            if (!hybridInput.startsWith("hybrid:")) {
                throw new IllegalArgumentException("Invalid hybrid format");
            }
            String payload = hybridInput.substring("hybrid:".length());
            // first part is encKeyB64, remaining is iv.ct (where iv and ct separated by '.')
            int firstDot = payload.indexOf('.');
            if (firstDot <= 0) throw new IllegalArgumentException("Invalid hybrid payload");

            String encKeyB64 = payload.substring(0, firstDot);
            String rest = payload.substring(firstDot + 1); // iv.ct

            byte[] encKey = Base64.getDecoder().decode(encKeyB64);
            // decrypt AES key with RSA
            byte[] aesKey = rsaDecryptOaep(rsaPrivateKey, encKey);

            // decrypt AES-GCM payload
            return decryptAesGcm(aesKey, rest, associatedData);
        }

        // ===================== Helper for text convenience =====================

        public static String encryptAesGcmToBase64String(byte[] aesKey, String plaintext, String aad) throws Exception {
            byte[] pt = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] aadBytes = aad != null ? aad.getBytes(StandardCharsets.UTF_8) : null;
            return encryptAesGcm(aesKey, pt, aadBytes);
        }

        public static String decryptAesGcmToString(byte[] aesKey, String ivAndCtBase64, String aad) throws Exception {
            byte[] aadBytes = aad != null ? aad.getBytes(StandardCharsets.UTF_8) : null;
            byte[] pt = decryptAesGcm(aesKey, ivAndCtBase64, aadBytes);
            return new String(pt, StandardCharsets.UTF_8);
        }



    }

