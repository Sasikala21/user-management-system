require('dotenv').config();
const jwt = require("jsonwebtoken");
const invalidatedTokens = [];
const refreshTokens = [];

verifyToken = async (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).json({ status: 'Failure', statusCode: 401, message: 'Access denied! No token provided!' });
    }
    if (invalidatedTokens.includes(token)) {
        return res.status(401).json({ status: 'Failure', statusCode: 401, message: 'Invalid token!' });
    } 
    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        req.user = decoded;
        req.userId = decoded._id;
        req.token = token;
        next();
    } catch (err) {
        return res.status(401).json({ status: 'Failure', statusCode: 401, message: 'Invalid token!' });
    }
};

invalidateToken = (token) => {
    invalidatedTokens.push(token);
};

refreshToken = (refreshToken) => {
    refreshTokens.push(refreshToken);
}
 
const authJWT = { verifyToken, invalidateToken, refreshToken };
module.exports = authJWT;