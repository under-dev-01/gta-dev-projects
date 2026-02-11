// jwt.middleware.js - Middleware de vérification JWT
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key';

const verifyToken = (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ 
        message: 'Token manquant' 
      });
    }

    // Check Bearer format
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({ 
        message: 'Format de token invalide. Utilisez: Bearer <token>' 
      });
    }

    const token = parts[1];

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Add user info to request
    req.userId = decoded.userId;
    req.userEmail = decoded.email;

    next();

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token expiré' 
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        message: 'Token invalide' 
      });
    }

    return res.status(500).json({ 
      message: 'Erreur de vérification du token',
      error: error.message 
    });
  }
};

// Optional auth - doesn't fail if no token
const optionalAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      req.userId = null;
      return next();
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      req.userId = null;
      return next();
    }

    const token = parts[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    req.userId = decoded.userId;
    req.userEmail = decoded.email;

    next();

  } catch (error) {
    req.userId = null;
    next();
  }
};

module.exports = {
  verifyToken,
  optionalAuth,
  JWT_SECRET
};
