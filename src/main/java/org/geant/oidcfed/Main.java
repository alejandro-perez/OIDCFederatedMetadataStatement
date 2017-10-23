package org.geant.oidcfed;

import org.apache.commons.io.IOUtils;
import org.json.JSONException;
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

public class Main {
    /* Disables SSL verification. ONLY FOR TESTING PURPOSES!!! */
    private static void disableSSLCertificateChecking() {
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
            @Override
            public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
            @Override
            public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
        }};
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        disableSSLCertificateChecking();
        try {
            JSONObject root_keys = new JSONObject(new String(Files.readAllBytes(Paths.get("rootkeys.json"))));
            String url = "https://oidcfed.inf.um.es:8777/.well-known/openid-configuration";
            //String url = "https://agaton-sax.com:8080/foo/rp-sms-multiple-l1/.well-known/openid-configuration";
            JSONObject discovery_doc = new JSONObject(
                    IOUtils.toString(new URL(url).openStream(), Charset.defaultCharset()));
            JSONObject federated_conf = FederatedMetadataStatement.getFederatedConfiguration(discovery_doc, root_keys);
        } catch (JSONException | IOException e) {
            System.out.println("There was a problem validating the metadata. Check track trace for more details");
            e.printStackTrace();
        }
    }
}