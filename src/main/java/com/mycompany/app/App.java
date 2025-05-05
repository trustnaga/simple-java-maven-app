package com.mycompany.app;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

import com.azure.core.util.polling.LongRunningOperationStatus;
import com.azure.core.util.polling.SyncPoller;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.CertificateIssuer;
import com.azure.security.keyvault.certificates.models.CertificateKeyCurveName;
import com.azure.security.keyvault.certificates.models.CertificateKeyType;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.certificates.models.SubjectAlternativeNames;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.certificates.models.CertificatePolicy;
import com.azure.security.keyvault.certificates.models.DeletedCertificate;
import com.azure.security.keyvault.certificates.models.CertificateOperation;

/**
 * Hello world!
 */
public class App {

    private static final String MESSAGE = "Hello World!";

    public App() {}
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String keyVaultName = "nagTestAKV2";
        String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";
        System.out.println("Key Vault URI: " + keyVaultUri);
        System.out.println("Key Vault Name: " + keyVaultName);
        String certificateName = "issuer";
        char[] NO_PASSWORD = "".toCharArray();
        String csrStr="-----BEGIN CERTIFICATE REQUEST-----\r\n" + //
                        "MIICuDCCAaACAQAwXjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlBBMREwDwYDVQQH\r\n" + //
                        "DAhDYXJsaXNsZTELMAkGA1UECgwCTVMxDDAKBgNVBAsMA0NTVTEUMBIGA1UEAwwL\r\n" + //
                        "ZGV2aWNlMDFuYWcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYhm1B\r\n" + //
                        "cJd2lBZjOrmp8TVShoXnKDLWA+EjNq6W14PT1Q+wM8Aw2cztO7ygPxAnoXa6DoG7\r\n" + //
                        "xl0xeVJxHlGjYZ+PvzjX4Qg78hP1Xq/wFztGjmARAn9+G5Sun25yfcofGszk55Tb\r\n" + //
                        "IYkmhA32B7iyAfMk/7S3F5I0Sy/V/1Q3Wqwn+WVh3inSh6ZhDLY9TelFONFaupT6\r\n" + //
                        "t0DA/MfvSA3yY81Zj+ApkbwxlrUL25FbbONZz+2TZcX6Xc43WHtWYZX/2QykFe8+\r\n" + //
                        "Tl4nhvcvgAfAOO9S5y46+5NTIqIprQugX9couuyVZ0BXly388eEU4awTiF5IWBd6\r\n" + //
                        "YV7nkki4PIrJLFDHAgMBAAGgFTATBgkqhkiG9w0BCQcxBgwEcGFzczANBgkqhkiG\r\n" + //
                        "9w0BAQsFAAOCAQEAGVDfsrJw2hQlM1jBGZuNu6dVX7OVuFfXTKVzmkzD/EBRycR3\r\n" + //
                        "4JQdUL/1yJncAt4Bz8SCdMssKUr9N+ZogK389RZgS9eFslYrBoAXBdmR1CGoTLch\r\n" + //
                        "qSR/8tsT6tghoVnkExg6mRRl4+ZR7RUp97gsvVOGmhqmDUBshDUA2a1AnL5Pcmv8\r\n" + //
                        "NadybHqTMbwY/1iGAQY1bGR1Ce6aWW5HShRciQzp9xQ4+/+Qmr/JgnDWkFRz3wVV\r\n" + //
                        "5364OxfpfBkzuF/0Tc5HGmqHo9bSVx0wfHj0GJqxqC4M5x+epFupSYB3nHft5smL\r\n" + //
                        "Ltxd/TdLkoUbyM0Ze4edb3GzG1ucalitXK+/QA==\r\n" + //
                        "-----END CERTIFICATE REQUEST-----\r\n" + //
        

        System.out.printf("key vault name = %s and kv uri = %s \n", keyVaultName, keyVaultUri);

        CertificateClient certificateClient = new CertificateClientBuilder()
            .vaultUrl(keyVaultUri)
            .credential(new DefaultAzureCredentialBuilder().build())
            .buildClient();

        KeyVaultCertificateWithPolicy clientCertificate = certificateClient.getCertificate(certificateName);

        System.out.printf("certificate %s", clientCertificate.toJsonString());


        //Retrieve the certificate as a secret value
        SecretClient secretClient = new SecretClientBuilder()
        .vaultUrl(keyVaultUri)
        .credential(new DefaultAzureCredentialBuilder().build())
        .buildClient();


        System.out.printf("Secret id %s", clientCertificate.getSecretId());
        KeyVaultSecret secret = secretClient.getSecret(certificateName);

        String secretValue = secret.getValue();
        byte[] decodedSecretValue = Base64.decode(secretValue);
        System.out.printf("**Secret value %s", secretValue);
        System.out.printf("***Secret value content type %s", secret.getProperties().getContentType());


        PrivateKey privateKey = null;
        if (secret.getProperties().getContentType().contains("pkcs12")) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new ByteArrayInputStream(decodedSecretValue), NO_PASSWORD);
            
            Key key = store.getKey(store.aliases().nextElement(), NO_PASSWORD);
            System.out.printf("****Key %s", key.toString());
            if (key instanceof PrivateKey) {
                privateKey = (PrivateKey) key;
            } else {
                System.out.println("Key is not a private key.");
            }
            
        }

         KeyVaultCertificate retrievedCertificate = certificateClient.getCertificate(certificateName);
        System.out.println("Certificate Name: " + retrievedCertificate.getName());
        byte[] certificateBytes = retrievedCertificate.getCer();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
       // X500Name Issuerx500name = new X500Name( x509Certificate.getSubjectX500Principal().getName());
        X500Name Issuerx500name = new JcaX509CertificateHolder(x509Certificate).getSubject();
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();


        // Read CSR from String
        // Convert the decoded bytes to a string
        String decodedCSRString = new String(csrStr);

        System.out.println("Decoded CSR String: " + decodedCSRString);
        PEMParser pemParser = new PEMParser(new StringReader(decodedCSRString));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParser.readObject();
        pemParser.close();
        System.out.println("CSR: " + csr.getSubject().toString());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
     
        ContentSigner csrContentSigner = csrBuilder.build(privateKey);

        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(
            Issuerx500name, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());
        
        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(x509Certificate.getPublicKey()));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        issuedCertBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        // Add intended key usage extension if needed
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

        // Add DNS name is cert is to used for SSL
        // issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
        //         new GeneralName(GeneralName.dNSName, "mydomain.local"),
        //         new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        // }));

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);
        issuedCert.verify(x509Certificate.getPublicKey(), BC_PROVIDER);

        System.out.println("Issuer: " + issuedCert.getIssuerX500Principal());
        System.out.println("Subject: " + issuedCert.getSubjectX500Principal());
        System.out.println("Serial Number: " + issuedCert.getSerialNumber());
        System.out.println("Valid From: " + issuedCert.getNotBefore());
        System.out.println("Valid To: " + issuedCert.getNotAfter());
        System.out.println("Signature Algorithm: " + issuedCert.getSigAlgName());
        System.out.println("Public Key: " + issuedCert.getPublicKey());

        writeCertToFileBase64Encoded(issuedCert, "issued-cert.cer");


        
        
    }

    static void writeCertToFileBase64Encoded(X509Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }

}
