package com.mycompany.app;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.azure.core.util.polling.SyncPoller;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.CertificateOperation;
import com.azure.security.keyvault.certificates.models.CertificatePolicy;
import com.azure.security.keyvault.certificates.models.DeletedCertificate;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

public class BouncyCastleCertificateGeneratorv2 {

    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) throws Exception{
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());


        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();
        
        // Initialize a new KeyPair generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);

        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)

        X500Name issuedCertSubject = new X500Name("CN=issued-cert");
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);


        //get the Root Cert & Private Key  frpom the keystore file root-cert.pfx
        // The root cert is self-signed, so the issuer and subject are the same
        // KeyStore sslKeyStore = KeyStore.getInstance("PKCS12", BC_PROVIDER);
        // FileInputStream fis = new FileInputStream("root-cert.pfx");
        // sslKeyStore.load(fis, "pass".toCharArray());
        // Key privateKey = sslKeyStore.getKey("root-cert", "pass".toCharArray());
        // //get root key pair from the Key
        // KeyPair rootKeyPair = new KeyPair(sslKeyStore.getCertificate("root-cert").getPublicKey(), (PrivateKey) privateKey);
        // System.out.println(rootKeyPair.getPrivate());
        // System.out.println(rootKeyPair.getPublic()); 


        // get the root cert from the Azure Key Vault certificate
        String keyVaultName = "nagTestAKV2";
        String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";
        String issuerCertificateName = "msrootca";
        System.out.print("Getting a certificate in " + keyVaultName + " called '" + issuerCertificateName + " ... ");
       
        CertificateClient certificateClient = new CertificateClientBuilder()
            .vaultUrl(keyVaultUri)
            .credential(new DefaultAzureCredentialBuilder().build())
            .buildClient();
  
        KeyVaultCertificate retrievedCertificate = certificateClient.getCertificate(issuerCertificateName);
        System.out.println("Your certificate's ID is '" + retrievedCertificate.getId() + "'.");


        
        byte[] certBytes = retrievedCertificate.getCer();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
        X500Name issuerx500name = new X500Name(x509Cert.getSubjectX500Principal().getName());
        PublicKey publicKey = x509Cert.getPublicKey();
        System.out.println("Your certificate's public key is '" + publicKey + "'.");

       

        //get private key from the Azure Key Vault certificate
        SecretClient secretClient = new SecretClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();
        KeyVaultSecret secret = secretClient.getSecret(issuerCertificateName);
        String privateKeyPem = secret.getValue();
        
        System.out.println("Your Private secret's ID is '" + secret.getId() + "'.");
        System.out.println("Your Private secret's value is '" + privateKeyPem + "'.");


        //read pk
        PemReader pemReader = new PemReader(new StringReader(privateKeyPem));
        
        PemObject pemObject = pemReader.readPemObject();
        if (pemObject == null) {
            throw new IllegalArgumentException("Invalid PEM format or content.");
        }
        byte[] keyBytes = pemObject.getContent();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
   
        KeyPair rootKeyPair = new KeyPair(publicKey, privateKey);
        System.out.println(rootKeyPair.getPrivate());
        System.out.println(rootKeyPair.getPublic()); 

       


        
    // Create a cert holder and export to X509Certificate from the sslKeyStore


    //  X509Certificate x509Cert= (X509Certificate)sslKeyStore.getCertificate("root-cert");
    //  X500Name issuerx500name = new X500Name( x509Cert.getSubjectX500Principal().getName());

        ContentSigner csrContentSigner = csrBuilder.build(rootKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(issuerx500name, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(x509Cert));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        // Add intended key usage extension if needed
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);


        // Verify the issued cert signature against the root (issuer) cert
        issuedCert.verify(x509Cert.getPublicKey(), BC_PROVIDER);

        writeCertToFileBase64Encoded(issuedCert, "issued-cert.cer");
        exportKeyPairToKeystoreFile(issuedCertKeyPair, issuedCert, "issued-cert", "issued-cert.pfx", "PKCS12", "pass");




        
    }

    static void exportKeyPairToKeystoreFile(KeyPair keyPair, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }

    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }
}
