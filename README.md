# GTA Dev Projects

Projet de tests d'authentification avec JWT.

## Structure du projet

```
gta-dev-projects/
├── controllers/
│   └── auth.controller.js    # Contrôleurs login/register
├── middleware/
│   └── jwt.middleware.js      # Middleware de vérification JWT
├── tests/
│   ├── auth.login.test.js     # Tests du login
│   ├── auth.register.test.js  # Tests du register
│   └── jwt.middleware.test.js # Tests du middleware JWT
├── package.json
├── jest.config.js
└── README.md
```

## Installation

```bash
npm install
```

## Lancer les tests

```bash
# Lancer tous les tests
npm test

# Lancer en mode watch
npm run test:watch

# Lancer avec coverage
npm run test:coverage
```

## Fonctionnalités testées

### Auth Controller - Login
- ✅ Connexion avec identifiants valides
- ✅ Rejet email inexistant
- ✅ Rejet mot de passe incorrect
- ✅ Validation des champs requis
- ✅ Retour d'un token JWT valide
- ✅ Exclusion du mot de passe de la réponse

### Auth Controller - Register
- ✅ Création d'utilisateur avec données valides
- ✅ Hashage du mot de passe (bcrypt)
- ✅ Rejet email déjà utilisé (409)
- ✅ Validation format email
- ✅ Validation longueur mot de passe (min 6 caractères)
- ✅ Validation champs requis
- ✅ Génération token JWT
- ✅ Assignation ID unique

### JWT Middleware
- ✅ Vérification token valide
- ✅ Rejet token manquant (401)
- ✅ Rejet format invalide (sans Bearer)
- ✅ Rejet token malformé
- ✅ Rejet token expiré
- ✅ Rejet token signé avec mauvaise clé
- ✅ Auth optionnel (optionalAuth)

## Configuration

La clé secrète JWT peut être configurée via la variable d'environnement `JWT_SECRET`.
Par défaut: `test-secret-key`

## Dépendances

- **jest**: Framework de test
- **supertest**: Tests HTTP (prêt pour l'intégration API)
- **jsonwebtoken**: Génération et vérification JWT
- **bcryptjs**: Hashage des mots de passe

## Issue GitHub

Ces tests ont été créés pour résoudre l'issue #2:
https://github.com/under-dev-01/gta-dev-projects/issues/2
