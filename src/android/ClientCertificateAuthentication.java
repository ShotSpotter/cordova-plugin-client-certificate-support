package de.jstd.cordova.plugin;

import static java.nio.file.Files.*;

import static de.jstd.cordova.plugin.customSSLSocketFactory.createCustomSSLSocketFactory;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;

import android.net.http.SslError;
import android.os.Build;

import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;

import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;

import org.apache.cordova.ICordovaClientCertRequest;
import org.apache.cordova.CallbackContext;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.KeyStore;

import java.io.File;
import java.io.InputStream;

import java.util.HashMap;
import java.util.Enumeration;
import java.util.Arrays;

import org.apache.cordova.engine.SystemWebView;
import org.apache.cordova.engine.SystemWebViewClient;
import org.apache.cordova.engine.SystemWebViewEngine;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import org.json.JSONArray;
import org.json.JSONException;
import android.app.admin.SecurityLog;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ClientCertificateAuthentication extends CordovaPlugin {

    public static final String SP_KEY_ALIAS = "SP_KEY_ALIAS";
    public static final String TAG = "soundthinking customSSL";


    private CordovaInterface cordova;
    private CordovaWebView webView;

    public class Cert {
        public X509Certificate[] mCertificates;
        public PrivateKey mPrivateKey;
    }

    public HashMap<String, Cert> certs = new HashMap<String, Cert>();
    
    X509Certificate[] mCertificates;
    PrivateKey mPrivateKey;
    String mAlias;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    public void pluginInitialize() {

        super.pluginInitialize();
//        String manufacturer = Build.MANUFACTURER;
//        String model = Build.MODEL;
//        int version = Build.VERSION.SDK_INT;
//        String versionRelease = Build.VERSION.RELEASE;
//
//        Log.e(TAG, "manufacturer " + manufacturer
//                + " \n model " + model
//                + " \n sdk version " + version
//                + " \n versionRelease " + versionRelease
//        );

        Provider provider = new BouncyCastleFipsProvider();
        Log.d(TAG, "creating new BouncyCastle fips provider: " + provider.getName());
        Security.insertProviderAt(provider, 1);

        Provider tlsProvider = new BouncyCastleJsseProvider(true, provider);
        Log.d(TAG, "creating new BouncyCastle tls provider: " + provider.getName());
        Security.insertProviderAt(tlsProvider, 1);

        SSLSocketFactory sslSocketFactory = createCustomSSLSocketFactory(tlsProvider);
        if (sslSocketFactory != null) {
            try {
                HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
                Log.d(TAG, "BouncyCastle Fips SSLSocketFactory is set in the WebView");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);


        // not sure why this wasn't there, or how it worked before...
        this.cordova = cordova;


        // Get the underlying Android WebView
        SystemWebView systemWebView = (SystemWebView) webView.getView();
        SystemWebViewEngine systemWebViewEngine = (SystemWebViewEngine) webView.getEngine();

        // Set custom WebViewClient
        systemWebView.setWebViewClient(new SystemWebViewClient(systemWebViewEngine) {

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                // Handle SSL errors here
                // For example, you can show an alert dialog to the user and decide whether to proceed or cancel the request
                handler.proceed(); // Proceed with the request (Not recommended for production, handle errors appropriately)
                // Or you can handle the error by canceling the request
                // handler.cancel();
            }

            @Override
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                Log.e(TAG, "errorCode: " + errorCode);
                Log.e(TAG, "description: " + description);
                Log.e(TAG, "failingUrl: " + failingUrl);
            }
            @Override
            public void onReceivedError (WebView view,
                                         WebResourceRequest request,
                                         WebResourceError error) {

                Log.e(TAG, "error: " + error.toString());
                Log.e(TAG, "errorCode: " + error.getErrorCode());
                Log.e(TAG, "description: " + error.getDescription());
                Log.e(TAG, "failingUrl: " + request.getUrl());
            }

            @Override
            public void onReceivedHttpError(WebView view,
                                            WebResourceRequest request, WebResourceResponse errorResponse) {
                Log.e(TAG, "error: " +  errorResponse.toString());
                Log.e(TAG, "reasonPhrase: " + errorResponse.getReasonPhrase());
                Log.e(TAG, "responseHeaders: " + errorResponse.getResponseHeaders());
                Log.e(TAG, "failingUrl: " + request.getUrl());
                super.onReceivedHttpError(view, request, errorResponse);

            }
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Log.d("WebView", "Request: " + request.getUrl());
                return super.shouldInterceptRequest(view, request);
            }
        });

    }

    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        return super.shouldAllowBridgeAccess(url);
    }

    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {

        Cert cert = certs.get(request.getHost());
        if (cert==null) {
            request.ignore();
            return true;
        }

        request.proceed(cert.mPrivateKey, cert.mCertificates);

        return true;
    }

    private Cert loadKeysFromKeyStore(String p12path, String p12password) {
        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BCFIPS");
            InputStream astream;
            if (p12path.startsWith("file:")) {
                File certFile = new File(p12path.substring(7));
                astream = newInputStream(certFile.toPath());

            } else {
                astream = cordova.getActivity().getApplicationContext().getAssets().open(p12path);
            }

//            File initialFile = new File(p12path);
//            InputStream astream = new FileInputStream(initialFile);
//
            keystore.load(astream, p12password.toCharArray());
            astream.close();
            Enumeration e = keystore.aliases();
            if (e.hasMoreElements()) {
                String ealias = (String) e.nextElement();
                PrivateKey key = (PrivateKey) keystore.getKey(ealias, p12password.toCharArray());
                java.security.cert.Certificate[]  chain = keystore.getCertificateChain(ealias);
                X509Certificate[] certs = Arrays.copyOf(chain, chain.length, X509Certificate[].class);
                Cert cert = new Cert();
                cert.mCertificates = certs;
                cert.mPrivateKey = key;
                return cert;
            } else
            {
                return null;
            }

        } catch (Exception ex)
        {
            Log.e(TAG, "error retreiving client certificate", ex);
            return null;
        }
    }



    @Override
    public boolean execute(String action, JSONArray a, CallbackContext c) throws JSONException {
        if (action.equals("registerAuthenticationCertificate")) {
            String p12path = a.getString(0);
            String p12password = a.getString(1);
            String host = a.getString(2);
            if (p12path.length() != 0 && p12password.length() != 0) {


                Cert cert = loadKeysFromKeyStore(p12path, p12password);
                certs.put(host, cert);


                c.success("Path of the certificate and password are registered for use");
                return true;
            } else {
                c.error("Path of the certificate or password id not defined");
                return false;
            }
        }
        return false;
    }
}
