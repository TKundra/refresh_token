const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const admin = require("./firebase_admin.js");

const ACCESS_TOKEN_EXPIRATION = process.env.ACCESS_TOKEN_EXP || '15m';
const REFRESH_TOKEN_EXPIRATION = process.env.REFRESH_TOKEN_EXPIRATION || '7d';

async function generateTokens(userId) {
    const accessToken = jwt.sign(
        { userId },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRATION }
    );
    const refreshToken = jwt.sign(
        { userId },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: REFRESH_TOKEN_EXPIRATION }
    );

    // hashed refresh token
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    // store hashed refresh token in DB (firestore)
    await admin.firestore()
        .collection("refresh_tokens")
        .doc(userId)
        .set({
            hashedRefreshToken,
            createdAt: Date.now(),
            expiresAt: Date.now() + (parseInt(process.env.REFRESH_TOKEN_EXPIRATION_INT) * 1000)
        });

    return {
        accessToken,
        refreshToken
    };
}

async function refreshTokens(oldRefreshToken) {
    // verify token
    const payload = jwt.verify(
        oldRefreshToken,
        process.env.JWT_REFRESH_SECRET,
    );

    // extract userId from payload
    const { userId } = payload ?? {};

    // get the token from DB
    const doc = await admin
        .firestore()
        .collection("refresh_tokens")
        .doc(userId)
        .get();

    // json data
    const data = doc.data();
    if (!data) throw new Error("No token found");

    // check if token is expired
    if (data.expiresAt < Date.now()) {
        throw new Error("Token expired");
    }

    /**
     * check validity
     * Compare original refresh token with hashed one that we have stored in DB
     * */
    const match = await bcrypt.compare(oldRefreshToken, data.hashedRefreshToken);
    if (!match) throw new Error("Invalid refresh token");

    // Delete old token
    await admin.firestore()
        .collection("refresh_tokens")
        .doc(userId)
        .delete();

    return generateTokens(userId);
}

module.exports = {
    generateTokens,
    refreshTokens,
};