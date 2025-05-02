package com.mycompany.app;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyVaultKey;

public class CertificateSignerV2 {
    public static final int SERIAL_NUMBER_LENGTH = 20;
    public static final int DEFAULT_KEY_SIZE = 2048;
    private static final String BC_PROVIDER = "BC";
        private static final String KEY_ALGORITHM = "RSA";
        private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String keyVaultName = "nagTestAKV2";
        String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";
        
        // // String  csrStr="-----BEGIN CERTIFICATE REQUEST-----\r\n" + //
        //                 "MIICizCCAXMCAQAwFTETMBEGA1UEAwwKWDEyMjQwMDAxMDCCASIwDQYJKoZIhvcN\r\n" + //
        //                 "AQEBBQADggEPADCCAQoCggEBANg+QB38GYz83zIPeucjtNhwETHBrpW3MBHSamnU\r\n" + //
        //                 "yRhXZYDMGyprqcZUARV/UVbwf/TrOuhVWEdCDrpkSKT8yABdVaI/gh2wDqoUa62i\r\n" + //
        //                 "bj7tOCoi1OBjhMklOa0RCGORr0PMYRe34MAyAuAPQd6Oj627iYol1sZ3pMjVNsYB\r\n" + //
        //                 "fevNnlvdKwpnnpNhSJvfmgvynls9LENREkaY98f64R8KaF4op6u2fypFI+oRpxpN\r\n" + //
        //                 "L0x+iRNn9hP29QH0dcgZxMKpeTyiSUThUKTsP/UxrbJ1MQvJCAiVkQzaTmq3wiMw\r\n" + //
        //                 "jFBaZIODoOVCaJAlKTS6jbWsHHf9hKbsd9+7iboCeeylejkCAwEAAaAxMC8GCSqG\r\n" + //
        //                 "SIb3DQEJDjEiMCAwCwYDVR0PBAQDAgUgMBEGCWCGSAGG+EIBAQQEAwICBDANBgkq\r\n" + //
        //                 "hkiG9w0BAQsFAAOCAQEAzGEJip7RpNYldoOqZX5wh4SRM7rGq2/6kAESif1aW4rw\r\n" + //
        //                 "T9ThEHeF7BzW3oiWBWKcgl1XIMLkXiffI/yqYSzFO+PwYUlSlqqkacEuPds5bEBM\r\n" + //
        //                 "4EfcWMBPtlQXXeg+MDISgps5+0YzGqjAgzU36QJvhWBCF1UsO+xiKI5c701qONDr\r\n" + //
        //                 "506Mw/YYBm2hFlxDKGg6NojWXsV7w94QMWxlvCjsumUjTsMSxEIpMh1kTNyW/TwP\r\n" + //
        //                 "wFKY+w1tMX3ZvSi5ZZBTIhwjdTyviUUDtnJ/dac48rAKTCc0qtMrQQ8+BGa2t+OU\r\n" + //
        //                 "2zoXw979a6eRs9/w+t58Bu3gariNzmvh2G9kAtcxBg==\r\n" + //
        //                 "-----END CERTIFICATE REQUEST-----";
       
        String certificateName = "issuer";
        CertificateClient certificateClient = new CertificateClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

        // KeyVaultCertificateWithPolicy certificateWithPolicy = certificateClient.getCertificate(certificateName);
        KeyVaultCertificate retrievedCertificate = certificateClient.getCertificate(certificateName);
        System.out.println("Certificate Name: " + retrievedCertificate.getName());
        byte[] certificateBytes = retrievedCertificate.getCer();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
        X500Name Issuerx500name = new X500Name( x509Certificate.getSubjectX500Principal().getName());


        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

        // Build the key client
        KeyClient keyClient = new KeyClientBuilder()
        .vaultUrl(keyVaultUri)
        .credential(new DefaultAzureCredentialBuilder().build())
        .buildClient();

        // Get the Key Vault Key
        KeyVaultKey keyVaultKey = keyClient.getKey(certificateName);
        JsonWebKey jsonWebKey = keyVaultKey.getKey();

        System.out.println("public Key: " + jsonWebKey.getN());
        System.out.println("private Key: " + jsonWebKey.getD());
        System.out.println("Key ID: " + keyVaultKey.getId());
        System.out.println("Key Type: " + keyVaultKey.getKeyType());
        System.out.println("Key Operations: " + keyVaultKey.getKeyOperations());

        // // Build the cryptography client
        // CryptographyClient cryptographyClient = new CryptographyClientBuilder()
        //         .keyIdentifier(keyVaultKey.getId())
        //         .credential(new DefaultAzureCredentialBuilder().build())
        //         .buildClient();

       
         
        // String decodedCSRString = new String(csrStr);

        // System.out.println("Decoded CSR String: " + decodedCSRString);
        // PEMParser pemParser = new PEMParser(new StringReader(decodedCSRString));
        // PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParser.readObject();
        // pemParser.close();

        
        // System.out.println("CSR: " + csr.getSubject().toString());
        // System.out.println("CSR Subject: " + csr.getSubject().toString());
        // System.out.println("CSR Public Key: " + csr.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        // System.out.println("CSR Signature Algorithm: " + csr.getSignatureAlgorithm().getAlgorithm().getId());

        // BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // // Setup start date to yesterday and end date for 1 year validity
        // Calendar calendar = Calendar.getInstance();
        // calendar.add(Calendar.DATE, -1);
        // Date startDate = calendar.getTime();

        // calendar.add(Calendar.YEAR, 1);
        // Date endDate = calendar.getTime();

        // // Use the Signed KeyPair and CSR to generate an issued Certificate
        // // Here serial number is randomly generated. In general, CAs use
        // // a sequence to generate Serial number and avoid collisions
        // X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(
        //         Issuerx500name, 
        //         issuedCertSerialNum, 
        //         startDate, 
        //         endDate, 
        //         csr.getSubject(), 
        //         csr.getSubjectPublicKeyInfo());

        // JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
        // // Add Extensions
        // // Use BasicConstraints to say that this Cert is not a CA
        // issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(x509Certificate));
        // issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        // // Add intended key usage extension if needed
        // issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));

        // // Add DNS name is cert is to used for SSL
        // issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
        //     new GeneralName(GeneralName.dNSName, "mydomain.local"),
        //     new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        // }));
         
        // // X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(contentSigner);
        // // X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

        // // issuedCert.verify(x509Certificate.getPublicKey(), BC_PROVIDER);
        
        // // System.out.println("Issuer: " + issuedCert.getIssuerX500Principal());
        // // System.out.println("Subject: " + issuedCert.getSubjectX500Principal());
        // // System.out.println("Serial Number: " + issuedCert.getSerialNumber());
        // // System.out.println("Valid From: " + issuedCert.getNotBefore());
        // // System.out.println("Valid To: " + issuedCert.getNotAfter());
        // // System.out.println("Signature Algorithm: " + issuedCert.getSigAlgName());
        // // System.out.println("Public Key: " + issuedCert.getPublicKey());

        
        


    }
    


    


}
