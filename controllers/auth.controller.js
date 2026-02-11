// auth.controller.js - Contrôleur d'authentification
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Mock database
const users = [];

const JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key';

// Register controller
const register = async (req, res) => {
  try {
    const { email, password, username } = req.body;

    // Validation
    if (!email || !password || !username) {
      return res.status(400).json({ 
        message: 'Tous les champs sont requis: email, password, username' 
      });
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Format email invalide' });
    }

    // Password strength
    if (password.length < 6) {
      return res.status(400).json({ 
        message: 'Le mot de passe doit contenir au moins 6 caractères' 
      });
    }

    // Check if user exists
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(409).json({ message: 'Cet email est déjà utilisé' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = {
      id: users.length + 1,
      email,
      username,
      password: hashedPassword,
      createdAt: new Date()
    };

    users.push(newUser);

    // Generate token
    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.status(201).json({
      message: 'Utilisateur créé avec succès',
      user: {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username
      },
      token
    });

  } catch (error) {
    return res.status(500).json({ message: 'Erreur serveur', error: error.message });
  }
};

// Login controller
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        message: 'Email et mot de passe requis' 
      });
    }

    // Find user
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.status(200).json({
      message: 'Connexion réussie',
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      },
      token
    });

  } catch (error) {
    return res.status(500).json({ message: 'Erreur serveur', error: error.message });
  }
};

// Get current user
const getMe = (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ message: 'Utilisateur non trouvé' });
  }

  return res.status(200).json({
    user: {
      id: user.id,
      email: user.email,
      username: user.username
    }
  });
};

// Clear users (for testing)
const clearUsers = () => {
  users.length = 0;
};

module.exports = {
  register,
  login,
  getMe,
  clearUsers,
  users
};
