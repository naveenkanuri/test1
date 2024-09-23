import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

public class DataSourceConfig {

    @Value("${ssl.rootcert}")
    private String sslRootCert;

    @Value("${ssl.cert}")
    private String sslCert;

    @Value("${ssl.key}")
    private String sslKey;

    public HikariDataSource dataSource() throws Exception {
        HikariConfig hikariConfig = new HikariConfig();
        // Configure database URL, username, password, etc.
        
        // Set SSL properties
        Properties properties = new Properties();
        properties.setProperty("sslmode", "verify-ca");
        properties.setProperty("sslfactory", CustomSSLSocketFactory.class.getName());
        hikariConfig.setDataSourceProperties(properties);

        return new HikariDataSource(hikariConfig);
    }

    public class CustomSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory socketFactory;

        public CustomSSLSocketFactory() throws Exception {
            // Create KeyStore for client certificates
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);

            // Load client cert and key from environment
            byte[] decodedCert = Base64.getDecoder().decode(stripPemHeaders(sslCert));
            byte[] decodedKey = Base64.getDecoder().decode(stripPemHeaders(sslKey));

            // Create certificate
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decodedCert));

            // Create private key
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

            // Set the key entry in the KeyStore
            keyStore.setKeyEntry("client-key", privateKey, null, new X509Certificate[]{cert});

            // Create a TrustStore for the server CA
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            X509Certificate rootCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(stripPemHeaders(sslRootCert))));
            trustStore.setCertificateEntry("server-ca", rootCert);

            // Create KeyManager and TrustManager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, null);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            socketFactory = context.getSocketFactory();
        }

        private String stripPemHeaders(String pem) {
            return pem.replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return socketFactory.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return socketFactory.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            return socketFactory.createSocket(s, host, port, autoClose);
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return socketFactory.createSocket(host, port);
        }

        // Implement other createSocket() methods similarly
    }
}
