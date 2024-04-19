package de.jstd.cordova.plugin;

import static java.nio.file.Files.*;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.http.SslError;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.security.keystore.KeyProperties;

import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.widget.Toast;

import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;

import org.apache.cordova.CordovaWebViewEngine;
import org.apache.cordova.ICordovaClientCertRequest;
import org.apache.cordova.CallbackContext;

import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.KeyStore;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.Enumeration;
import java.util.Arrays;

import org.apache.cordova.engine.SystemWebView;
import org.apache.cordova.engine.SystemWebViewClient;
import org.apache.cordova.engine.SystemWebViewEngine;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ClientCertificateAuthentication extends CordovaPlugin {

    public class Cert {
        public X509Certificate[] mCertificates;
        public PrivateKey mPrivateKey;
    }

    public static final String SP_KEY_ALIAS = "SP_KEY_ALIAS";
    public static final String TAG = "client-cert-auth";

    public HashMap<String, Cert> certs = new HashMap<String, Cert>();
    
    X509Certificate[] mCertificates;
    PrivateKey mPrivateKey;
    String mAlias;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        // Get the underlying Android WebView
        SystemWebView systemWebView = (SystemWebView) webView.getView();
        SystemWebViewEngine systemWebViewEngine = (SystemWebViewEngine) webView.getEngine();

        // Set custom WebViewClient
        systemWebView.setWebViewClient(new SystemWebViewClient(systemWebViewEngine) {
//            @Override
//            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
//                // Handle SSL errors here
//                // For example, you can show an alert dialog to the user and decide whether to proceed or cancel the request
//                handler.proceed(); // Proceed with the request (Not recommended for production, handle errors appropriately)
//                // Or you can handle the error by canceling the request
//                // handler.cancel();
//            }

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
            KeyStore keystore = KeyStore.getInstance("PKCS12");
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
