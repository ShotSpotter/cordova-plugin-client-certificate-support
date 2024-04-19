/*global cordova, module*/

module.exports = {
    registerAuthenticationCertificate: function (certificatePath, certificatePassword, host, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "ClientCertificateAuthentication", "registerAuthenticationCertificate", [certificatePath, certificatePassword, host]);
    }
};