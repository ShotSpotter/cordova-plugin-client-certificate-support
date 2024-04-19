interface CordovaClientCertificatePlugin {
    registerAuthenticationCertificate(certificatePath: string, certificatePassword: string, host: string, successCallback: (message: string) => void, errorCallback: (error: string) => void);
}

declare var clientCertificate: CordovaClientCertificatePlugin;