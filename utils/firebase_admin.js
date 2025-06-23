const admin = require("firebase-admin");
const serviceAccount = require("../jwt-app-46b80-firebase-adminsdk-fbsvc-1336a0434a.json");

// Handle private key formatting
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

module.exports = admin;