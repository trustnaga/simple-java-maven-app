package com.mycompany.app;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.models.KeyVaultKey;

import org.bouncycastle.operator.ContentSigner;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class CertificateSigner {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String keyVaultName = "nagTestAKV";
        String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";

       
        String certificateName = "issuer";
        String  csrStr="-----BEGIN CERTIFICATE REQUEST-----\r\n" + //
                        "MIICizCCAXMCAQAwFTETMBEGA1UEAwwKWDEyMjQwMDAxMDCCASIwDQYJKoZIhvcN\r\n" + //
                        "AQEBBQADggEPADCCAQoCggEBANg+QB38GYz83zIPeucjtNhwETHBrpW3MBHSamnU\r\n" + //
                        "yRhXZYDMGyprqcZUARV/UVbwf/TrOuhVWEdCDrpkSKT8yABdVaI/gh2wDqoUa62i\r\n" + //
                        "bj7tOCoi1OBjhMklOa0RCGORr0PMYRe34MAyAuAPQd6Oj627iYol1sZ3pMjVNsYB\r\n" + //
                        "fevNnlvdKwpnnpNhSJvfmgvynls9LENREkaY98f64R8KaF4op6u2fypFI+oRpxpN\r\n" + //
                        "L0x+iRNn9hP29QH0dcgZxMKpeTyiSUThUKTsP/UxrbJ1MQvJCAiVkQzaTmq3wiMw\r\n" + //
                        "jFBaZIODoOVCaJAlKTS6jbWsHHf9hKbsd9+7iboCeeylejkCAwEAAaAxMC8GCSqG\r\n" + //
                        "SIb3DQEJDjEiMCAwCwYDVR0PBAQDAgUgMBEGCWCGSAGG+EIBAQQEAwICBDANBgkq\r\n" + //
                        "hkiG9w0BAQsFAAOCAQEAzGEJip7RpNYldoOqZX5wh4SRM7rGq2/6kAESif1aW4rw\r\n" + //
                        "T9ThEHeF7BzW3oiWBWKcgl1XIMLkXiffI/yqYSzFO+PwYUlSlqqkacEuPds5bEBM\r\n" + //
                        "4EfcWMBPtlQXXeg+MDISgps5+0YzGqjAgzU36QJvhWBCF1UsO+xiKI5c701qONDr\r\n" + //
                        "506Mw/YYBm2hFlxDKGg6NojWXsV7w94QMWxlvCjsumUjTsMSxEIpMh1kTNyW/TwP\r\n" + //
                        "wFKY+w1tMX3ZvSi5ZZBTIhwjdTyviUUDtnJ/dac48rAKTCc0qtMrQQ8+BGa2t+OU\r\n" + //
                        "2zoXw979a6eRs9/w+t58Bu3gariNzmvh2G9kAtcxBg==\r\n" + //
                        "-----END CERTIFICATE REQUEST-----";




        //Load the root certificate from the Azure Key Vault
        // Build the certificate client
        CertificateClient certificateClient = new CertificateClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

        // KeyVaultCertificateWithPolicy certificateWithPolicy = certificateClient.getCertificate(certificateName);
        KeyVaultCertificate retrievedCertificate = certificateClient.getCertificate(certificateName);

         // Convert the certificate to X509Certificate
         byte[] certificateBytes = retrievedCertificate.getCer();
         CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
         X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
 
         // Load the certificate into a KeyStore
         KeyStore keyStore = KeyStore.getInstance("JKS");
         keyStore.load(null, null);
         keyStore.setCertificateEntry(certificateName, x509Certificate);


          // Build the key client
        KeyClient keyClient = new KeyClientBuilder()
        .vaultUrl(keyVaultUri)
        .credential(new DefaultAzureCredentialBuilder().build())
        .buildClient();

        // Get the Key Vault Key
        KeyVaultKey keyVaultKey = keyClient.getKey(certificateName);

        // Build the cryptography client
        CryptographyClient cryptographyClient = new CryptographyClientBuilder()
                .keyIdentifier(keyVaultKey.getId())
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();
        // Create the ContentSigner using the cryptography client
        ContentSigner contentSigner = new ContentSigner() {
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
            }

            @Override
            public OutputStream getOutputStream() {
                return new ByteArrayOutputStream() {
                    @Override
                    public void close() throws IOException {
                        byte[] dataToSign = this.toByteArray();
                        SignResult signResult = cryptographyClient.signData(SignatureAlgorithm.RS256, dataToSign);
                        super.write(signResult.getSignature());
                    }
                };
            }

            @Override
            public byte[] getSignature() {
                // Sign data using the cryptography client
                SignResult signResult = cryptographyClient.signData(SignatureAlgorithm.RS256, new byte[0]);
                return signResult.getSignature();
            }
        };
 
         // Optionally, you can print the certificate details
         System.out.println("Certificate Subject: " + x509Certificate.getSubjectX500Principal().getName());
         System.out.println("Certificate Issuer: " + x509Certificate.getIssuerX500Principal().getName());
         System.out.println("Certificate Serial Number: " + x509Certificate.getSerialNumber());
         
        // Load the signing certificate
        // KeyStore keyStore = KeyStore.getInstance("PKCS12");
        // keyStore.load(new FileInputStream("root.cert.pfx"), password.toCharArray());
        // PrivateKey signingKey = (PrivateKey) keyStore.getKey("alias", password.toCharArray());
        X509Certificate signingCertificate = (X509Certificate) keyStore.getCertificate(certificateName);

        // Read CSR from String
        // Convert the decoded bytes to a string
        String decodedCSRString = new String(csrStr);

        System.out.println("Decoded CSR String: " + decodedCSRString);
        PEMParser pemParser = new PEMParser(new StringReader(decodedCSRString));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParser.readObject();
        pemParser.close();
        System.out.println("CSR: " + csr.getSubject().toString());
        // Alternatively, read CSR from file


        // Extract common name from CSR
        JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(csr);
        String commonName = jcaRequest.getSubject().toString();

        // Extract public key from CSR
        PublicKey publicKey = jcaRequest.getPublicKey();

        // Create certificate
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365 * 24 * 60 * 60 * 1000L); // 1 year validity

        X500Name issuer = new X500Name(signingCertificate.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + commonName);
        BigInteger serial = BigInteger.valueOf(now);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                startDate,
                endDate,
                subject,
                publicKey
        );

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation));

        // ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(signingKey);
        X509CertificateHolder holder = certBuilder.build(contentSigner);

        X509Certificate deviceCert = new JcaX509CertificateConverter().getCertificate(holder);

        // Export certificates to PEM files
        try (Writer writer = new FileWriter("device1.cert.pem")) {
            writer.write("-----BEGIN CERTIFICATE-----\n");
            writer.write(Base64.getEncoder().encodeToString(deviceCert.getEncoded()));
            writer.write("\n-----END CERTIFICATE-----\n");
        }

        try (Writer writer = new FileWriter("device1-full-chain.cert.pem")) {
            writer.write("-----BEGIN CERTIFICATE-----\n");
            writer.write(Base64.getEncoder().encodeToString(deviceCert.getEncoded()));
            writer.write("\n-----END CERTIFICATE-----\n");
            writer.write("-----BEGIN CERTIFICATE-----\n");
            writer.write(Base64.getEncoder().encodeToString(signingCertificate.getEncoded()));
            writer.write("\n-----END CERTIFICATE-----\n");
        }

        System.out.println("Certificates exported to PEM files");
    }
}