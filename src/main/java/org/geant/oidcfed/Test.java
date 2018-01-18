package org.geant.oidcfed;

import com.nimbusds.jose.jwk.JWKSet;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;

public class Test {
    /* Disables SSL verification. ONLY FOR TESTING PURPOSES!!! */
    private static void disableSSLCertificateChecking() {
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
            }
        }};
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        disableSSLCertificateChecking();
        JSONObject root_keys = null;
        JWKSet signing_keys = null;
        JSONObject discovery_doc = null;
        JSONObject sms = null;
        FederatedMetadataStatement.MAX_CLOCK_SKEW = 0;
        try {
            root_keys = new JSONObject(new String(Files.readAllBytes(Paths.get("rootkeys.json"))));
            signing_keys = JWKSet.parse(new String(Files.readAllBytes(Paths.get("signing_keys.jwks"))));
            sms = new JSONObject(new String(Files.readAllBytes(Paths.get("sms.json"))));
            String url = "https://minifed.lxd:8777/.well-known/openid-configuration";
            discovery_doc = new JSONObject(IOUtils.toString(new URL(url).openStream(), Charset.defaultCharset()));
        } catch (IOException | ParseException e ) {
            System.out.println("Could not get the discovery document or root keys: " + e.getMessage());
            System.exit(-1);
        }
        try {
            discovery_doc = new JSONObject("{\"claim1\": \"aaa\"}");
            discovery_doc.put("metadata_statements", FederatedMetadataStatement.genFederatedConfiguration(
                    new JSONObject("{\"claim1\": \"aaa\"}"), sms, signing_keys, "https://testrp"));
            System.out.println(discovery_doc.toString());

            FederatedMetadataStatement.MAX_CLOCK_SKEW = 0;
            JSONObject federated_conf = FederatedMetadataStatement.getFederatedConfiguration(discovery_doc, root_keys);
        } catch (InvalidStatementException e) {
            System.out.println("There was a problem validating the metadata: " + e.getMessage());
        }
    }
}
