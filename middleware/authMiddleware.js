const jwt = require('jsonwebtoken');

function authMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header) {
        return res.status(401).json({ error: 'Authorization header is required' });
    }

    const [bearer, token] = header.split(' ');
    if (bearer !== 'Bearer' || !token) {
        return res.status(401).json({ error: 'Invalid authorization header format' });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

        // Check if token is expired
        if (payload.exp && payload.exp < Date.now() / 1000) {
            return res.status(401).json({ error: 'Token has expired' });
        }

        req.userId = payload.userId;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token has expired' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        throw error;
    }
}

module.exports = authMiddleware;