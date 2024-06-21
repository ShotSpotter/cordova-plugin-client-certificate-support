package de.jstd.cordova.plugin;

import android.util.Log;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

public class customSSLSocketFactory {
    private static final String TAG = "soundthinking customSSL";

    public static SSLSocketFactory createCustomSSLSocketFactory(Provider provider) {

        Log.d(TAG, "createCustomSSLSocketFactory");
        try {

            String algorithm = TrustManagerFactory.getDefaultAlgorithm();
            Log.d(TAG, "trustManagerFactory default algorithm: " + algorithm);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm, provider);
            trustManagerFactory.init((KeyStore) null);

            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
                throw new NoSuchAlgorithmException("Unexpected default trust managers: " + java.util.Arrays.toString(trustManagers));
            }
            X509TrustManager trustManager =  (X509TrustManager) trustManagers[0];

            // Wrap the TrustManager with CustomTrustManagerWrapper
//            CustomTrustManagerWrapper customWrapper = new CustomTrustManagerWrapper(trustManager);


            String sslAlgo = "TLSv1.1";  // tested other std algo names
            SSLContext sslContext;
            if (provider != null) {
                sslContext = SSLContext.getInstance(sslAlgo, provider);
            } else {
                sslContext = SSLContext.getInstance(sslAlgo);
            }

            sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());

            // debug information only
            SSLContext inUseContext = SSLContext.getInstance(sslAlgo);
            Provider inUseProvider = inUseContext.getProvider();
            String name = inUseProvider.getName();
            Log.d(TAG, "custom Provider name: " +  name + " is being used for SSL");
            String protocol = inUseContext.getProtocol();
            Log.d(TAG, "protocol: " + protocol);

            // return the socketFactory;
            // used to set the global socketFactory:
            //   HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            Log.d(TAG, "error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}

