/*global cordova, module*/

module.exports = {
    registerAuthenticationCertificate: function (certificatePath, certificatePassword, host, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "ClientCertificate", "registerAuthenticationCertificate", [certificatePath, certificatePassword, host]);
    }
};