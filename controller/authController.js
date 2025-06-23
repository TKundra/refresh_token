const express = require('express');
const admin = require('../utils/firebase_admin.js');
const verifyPassword = require('../utils/firebase_auth.js');
const {
    generateTokens,
    refreshTokens
} = require("../utils/auth_service.js");

const router = express.Router();

router.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        const userRecord = await admin.auth().createUser({ email, password });
        res.status(201).json({ uid: userRecord.uid });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Verify credentials using Firebase Auth REST API
        const authResult = await verifyPassword(email, password);
        
        // Generate our JWT tokens
        const {
            accessToken,
            refreshToken
        } = await generateTokens(authResult.uid);

        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", // use true in production
          sameSite: "Strict",
          path: "/", // important to match with clearCookie path
          maxAge: 30 * 24 * 60 * 60 * 1000 // e.g. 30 days
        });

        // send data to client
        res.json({
            accessToken,
            user: {
                uid: authResult.uid,
                email: authResult.email
            }
        });
    } catch (err) {
        res.status(401).json({ error: "Invalid credentials" });
    }
});

router.post('/refresh', async (req, res) => {
    // get refresh token from cookies
    const { refreshToken: rt } = req.body;
    if (!rt) return res.status(401).json({ error: 'No refresh token' });

    try {
        // on the basis of old refresh token - get new tokens
        const { accessToken, refreshToken } = await refreshTokens(rt);

        // Set new refreshToken in cookie
        res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'Strict',
          path: '/', // make sure path matches
        });

        res.json({ accessToken });
    } catch (err) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

router.post('/logout', async (req, res) => {
    const userId = req.userId;
    await admin.firestore().collection('refresh_tokens').doc(userId).delete();

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      path: '/', // Must match path used when setting the cookie
    });

    res.sendStatus(200); // or res.json({ success: true });

});

module.exports = router;