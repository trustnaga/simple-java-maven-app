package com.mycompany.app;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.azure.core.util.polling.LongRunningOperationStatus;
import com.azure.core.util.polling.SyncPoller;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.CertificateContentType;
import com.azure.security.keyvault.certificates.models.CertificateIssuer;
import com.azure.security.keyvault.certificates.models.CertificateKeyCurveName;
import com.azure.security.keyvault.certificates.models.CertificateKeyType;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.certificates.models.MergeCertificateOptions;
import com.azure.security.keyvault.certificates.models.SubjectAlternativeNames;
import com.azure.security.keyvault.certificates.models.CertificatePolicy;
import com.azure.security.keyvault.certificates.models.DeletedCertificate;
import com.azure.security.keyvault.certificates.models.ImportCertificateOptions;
import com.azure.security.keyvault.certificates.models.CertificateOperation;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import java.security.cert.X509Certificate;

/**
 * Hello world!
 */
public class ImportCert {

    private static final String MESSAGE = "Hello World!";

    public ImportCert() {}

    public static void main(String[] args) {
        String keyVaultName = "tests12323";
        String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";
        System.out.println("Key Vault URI: " + keyVaultUri);
        System.out.println("Key Vault Name: " + keyVaultName);

        String  csrStr="MIICizCCAXMCAQAwFTETMBEGA1UEAwwKWDEyMjQwMDAxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANg+QB38GYz83zIPeucjtNhwETHBrpW3MBHSamnUyRhXZYDMGyprqcZUARV/UVbwf/TrOuhVWEdCDrpkSKT8yABdVaI/gh2wDqoUa62ibj7tOCoi1OBjhMklOa0RCGORr0PMYRe34MAyAuAPQd6Oj627iYol1sZ3pMjVNsYBfevNnlvdKwpnnpNhSJvfmgvynls9LENREkaY98f64R8KaF4op6u2fypFI+oRpxpNL0x+iRNn9hP29QH0dcgZxMKpeTyiSUThUKTsP/UxrbJ1MQvJCAiVkQzaTmq3wiMwjFBaZIODoOVCaJAlKTS6jbWsHHf9hKbsd9+7iboCeeylejkCAwEAAaAxMC8GCSqGSIb3DQEJDjEiMCAwCwYDVR0PBAQDAgUgMBEGCWCGSAGG+EIBAQQEAwICBDANBgkqhkiG9w0BAQsFAAOCAQEAzGEJip7RpNYldoOqZX5wh4SRM7rGq2/6kAESif1aW4rwT9ThEHeF7BzW3oiWBWKcgl1XIMLkXiffI/yqYSzFO+PwYUlSlqqkacEuPds5bEBM4EfcWMBPtlQXXeg+MDISgps5+0YzGqjAgzU36QJvhWBCF1UsO+xiKI5c701qONDr506Mw/YYBm2hFlxDKGg6NojWXsV7w94QMWxlvCjsumUjTsMSxEIpMh1kTNyW/TwPwFKY+w1tMX3ZvSi5ZZBTIhwjdTyviUUDtnJ/dac48rAKTCc0qtMrQQ8+BGa2t+OU2zoXw979a6eRs9/w+t58Bu3gariNzmvh2G9kAtcxBg==";

        System.out.printf("key vault name = %s and kv uri = %s \n", keyVaultName, keyVaultUri);

        CertificateClient certificateClient = new CertificateClientBuilder()
            .vaultUrl(keyVaultUri)
            .credential(new DefaultAzureCredentialBuilder().build())
            .buildClient();

        byte[] csrBytes = Base64.getDecoder().decode(csrStr);
        System.out.println("CSR bytes: " + Arrays.toString(csrBytes));
        String certificateName = "myCertificate07";

        CertificatePolicy policy = new CertificatePolicy("myIssuer", "CN = X122400010");
        SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> certPoller = certificateClient.beginCreateCertificate(certificateName, policy);
        certPoller.waitUntil(LongRunningOperationStatus.SUCCESSFULLY_COMPLETED);
        KeyVaultCertificate cert = certPoller.getFinalResult();
        System.out.printf("Certificate created with name %s%n", cert.getName());
        System.out.printf("Certificate created with ID: %s%n", cert.getId());
        
        List<byte[]> x509CertificatesToMerge = new ArrayList<>();
        x509CertificatesToMerge.add(csrBytes);
       

        MergeCertificateOptions config =
     new MergeCertificateOptions(certificateName, x509CertificatesToMerge)
         .setEnabled(false);
 KeyVaultCertificate mergedCertificate = certificateClient.mergeCertificate(config);
 System.out.printf("Received Certificate with name %s and key id %s%n",
     mergedCertificate.getProperties().getName(), mergedCertificate.getKeyId());

        // try {
        //     PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);
        //     CertificatePolicy certificatePolicy = new CertificatePolicy("myIssuer", "CN=X122400010")
        //         .setExportable(true)
        //         .setKeyType(CertificateKeyType.RSA)
        //         .setKeySize(2048)
        //         .setContentType(CertificateContentType.PKCS12)
        //         .setValidityInMonths(12);
        //     System.out.println("CSR subject: " + csr.getSubject().toString());

        //     certificateClient.beginCreateCertificate(certificateName, certificatePolicy).waitForCompletion();
        //     X509Certificate intermediateCertificate = certificateClient.getCertificate(certificateName).getCer()
        // } catch (Exception e) {
        //     System.out.println("Error parsing CSR: " + e.getMessage());
        // }

        // CertificateIssuer issuer = new CertificateIssuer("myIssuer", "Test");
        // CertificateIssuer myIssuer = certificateClient.createIssuer(issuer);

        // System.out.printf("Issuer created with name %s and provider %s", myIssuer.getName(), myIssuer.getProvider());

        // // Let's fetch the issuer we just created from the key vault.
        // myIssuer = certificateClient.getIssuer("myIssuer");
        // System.out.printf("Issuer fetched with name %s and provider %s", myIssuer.getName(), myIssuer.getProvider());


        // String certificateName = "myCertificate05";

        // System.out.print("Creating a certificate in " + keyVaultName + " called '" + certificateName + " ... ");
        // Map<String, String> tags = new HashMap<>();
        // tags.put("foo", "bar");
        // 
        
        // certificateClient.beginCreateCertificate(certificateName, policy).getFinalResult();
        // List<byte[]> byteArray = new ArrayList<>();
        // byteArray.add(Base64.getDecoder().decode(csr));
        // MergeCertificateOptions mergeCertificateOptions = new MergeCertificateOptions(certificateName, 
        // byteArray).setEnabled(true);
        // certificateClient.mergeCertificate(mergeCertificateOptions);
        // KeyVaultCertificate retrievedCertificate = certificateClient.getCertificate(certificateName);
        // System.out.println("Your certificate's ID is '" + retrievedCertificate.getId() + "'.");
        // System.out.println("Deleting your certificate from " + keyVaultName + " ... ");

        // SyncPoller<DeletedCertificate, Void> deletionPoller = certificateClient.beginDeleteCertificate(certificateName);
        // deletionPoller.waitForCompletion();

        // System.out.print("done.");
    }

    public String getMessage() {
        return MESSAGE;
    }
}
