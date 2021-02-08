import java.io.*;
import java.util.*;
import javax.net.ssl.*;
import java.security.KeyStore;

public class SSLServerHandshake {
    
    public static void main(String[] args) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");

        // You need to explicitly create a create a custom KeyManager

        // Keystores
        KeyStore keyKS = KeyStore.getInstance("PKCS12");
        keyKS.load(new FileInputStream("serverCert.p12"), 
            "password".toCharArray());

        // Generate KeyManager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(keyKS, "password".toCharArray());
        KeyManager[] kms = kmf.getKeyManagers();

        // Code to substitute MyX509ExtendedKeyManager
        if (!(kms[0] instanceof X509ExtendedKeyManager)) {
            throw new Exception("kms[0] not X509ExtendedKeyManager");
        }

        // Create a new KeyManager array and set the first index 
        // of the array to an instance of MyX509ExtendedKeyManager.
        // Notice how creating this object is done by passing in the 
        // existing default X509ExtendedKeyManager 
        kms = new KeyManager[] { 
            new MyX509ExtendedKeyManager((X509ExtendedKeyManager) kms[0])};

        // Initialize SSLContext using the new KeyManager
        ctx.init(kms, null, null);

        // Instead of using SSLServerSocketFactory.getDefault(), 
        // get a SSLServerSocketFactory based on the SSLContext
        SSLServerSocketFactory sslssf = ctx.getServerSocketFactory();
        SSLServerSocket sslServerSocket = 
            (SSLServerSocket) sslssf.createServerSocket(9999);
        SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
        SSLParameters sslp = sslSocket.getSSLParameters();
        String[] serverAPs ={"one","two","three"};
        sslp.setApplicationProtocols(serverAPs);
        sslSocket.setSSLParameters(sslp);
        sslSocket.startHandshake();

        String ap = sslSocket.getApplicationProtocol();
        System.out.println("Application Protocol server side: \"" + ap + "\"");

        InputStream sslIS = sslSocket.getInputStream();
        OutputStream sslOS = sslSocket.getOutputStream();
        sslIS.read();
        sslOS.write(85);
        sslOS.flush();

        sslSocket.close();
        sslServerSocket.close();
    }
}
