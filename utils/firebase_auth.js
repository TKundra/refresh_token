async function verifyPassword(email, password) {
    try {
        const fetch = (await import('node-fetch')).default;
        const response = await fetch(
            `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email,
                    password,
                    returnSecureToken: false,
                }),
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error?.message || 'Authentication failed');
        }

        return {
            uid: data.localId,
            email: data.email
        };
    } catch (error) {
        throw new Error('Invalid credentials');
    }
}

module.exports = verifyPassword;