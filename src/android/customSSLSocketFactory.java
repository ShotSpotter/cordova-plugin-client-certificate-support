package de.jstd.cordova.plugin;

import android.util.Log;

import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;


import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.conscrypt.Conscrypt;
//import org.spongycastle.*;
//import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class customSSLSocketFactory {
    private static final String TAG = "soundthinking customSSL";

    private static Provider getProvider(String name) {
        Provider existingProvider = Security.getProvider(name);
        Provider provider = null;
        if (existingProvider == null) {

            if (name.equals("Conscrypt")) {
                provider = Conscrypt.newProvider();
                Security.insertProviderAt(provider, 1);
                String realName = provider.getName();
                Log.d(TAG, "creating new Conscrypt ssl provider: " + realName);
            } else if(name.equals("")) {

                provider = new BouncyCastleJsseProvider();
                Security.insertProviderAt(provider, 1);
                String realName = provider.getName();
                Log.d(TAG, "creating new BouncyCastle ssl provider: " + realName);
            }
        } else {
            String realName = existingProvider.getName();
            Log.d(TAG, "using existing provider: " + realName);
        }

        return provider;
    }

    public static SSLSocketFactory createCustomSSLSocketFactory(CordovaInterface cordova, CordovaWebView webView) {

        Log.d(TAG, "createCustomSSLSocketFactory");
        try {

//            Security.removeProvider("BC");
            String providerName = "Conscrypt";
//            String providerName = "";
            Provider provider = getProvider(providerName);

            // Set the default TrustManager algorithm property to "X509" for the Bouncy Castle provider
//            System.setProperty("ssl.TrustManagerFactory.algorithm", "X509");

            String algorithm = TrustManagerFactory.getDefaultAlgorithm();
//            String algorithm = "ECB";
//            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
//                    algorithm, provider);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
            trustManagerFactory.init((KeyStore) null);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
                throw new NoSuchAlgorithmException("Unexpected default trust managers: " + java.util.Arrays.toString(trustManagers));
            }
            X509TrustManager trustManager = (X509TrustManager) trustManagers[0];

            SSLContext sslContext = SSLContext.getInstance("TLS", provider);

            sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());

            SSLContext inUseContext = SSLContext.getInstance("TLS");
            Provider inUseProvider = inUseContext.getProvider();
            String name = inUseProvider.getName();
            Log.d(TAG, "custom Provider name: " +  name + " is being used for SSL");
            String protocol = inUseContext.getProtocol();
            Log.d(TAG, "protocol: " + protocol);


            return sslContext.getSocketFactory();
        } catch (Exception e) {

            e.printStackTrace();
            return null;
        }
    }
}

