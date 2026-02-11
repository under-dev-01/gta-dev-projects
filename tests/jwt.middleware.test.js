// tests/jwt.middleware.test.js - Tests pour le middleware JWT
const jwt = require('jsonwebtoken');
const { verifyToken, optionalAuth, JWT_SECRET } = require('../middleware/jwt.middleware');

describe('JWT Middleware', () => {
  let mockReq;
  let mockRes;
  let nextMock;

  beforeEach(() => {
    mockReq = {
      headers: {}
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    nextMock = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('verifyToken', () => {
    test('devrait passer avec un token JWT valide', () => {
      const token = jwt.sign(
        { userId: 1, email: 'test@example.com' },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      mockReq.headers.authorization = `Bearer ${token}`;

      verifyToken(mockReq, mockRes, nextMock);

      expect(nextMock).toHaveBeenCalled();
      expect(mockReq.userId).toBe(1);
      expect(mockReq.userEmail).toBe('test@example.com');
    });

    test('devrait rejeter une requête sans header Authorization', () => {
      verifyToken(mockReq, mockRes, nextMock);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Token manquant'
        })
      );
      expect(nextMock).not.toHaveBeenCalled();
    });

    test('devrait rejeter un token avec format invalide (sans Bearer)', () => {
      const token = jwt.sign({ userId: 1 }, JWT_SECRET);
      mockReq.headers.authorization = token;

      verifyToken(mockReq, mockRes, nextMock);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Format de token invalide. Utilisez: Bearer <token>'
        })
      );
    });

    test('devrait rejeter un token malformé', () => {
      mockReq.headers.authorization = 'Bearer invalid-token';

      verifyToken(mockReq, mockRes, nextMock);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Token invalide'
        })
      );
    });

    test('devrait rejeter un token expiré', () => {
      const token = jwt.sign(
        { userId: 1 },
        JWT_SECRET,
        { expiresIn: '-1s' } // Déjà expiré
      );

      mockReq.headers.authorization = `Bearer ${token}`;

      verifyToken(mockReq, mockRes, nextMock);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Token expiré'
        })
      );
    });

    test('devrait rejeter un token signé avec une clé secrète différente', () => {
      const wrongToken = jwt.sign(
        { userId: 1 },
        'wrong-secret-key'
      );

      mockReq.headers.authorization = `Bearer ${wrongToken}`;

      verifyToken(mockReq, mockRes, nextMock);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Token invalide'
        })
      );
    });

    test('devrait rejeter un token Bearer vide', () => {
      mockReq.headers.authorization = 'Bearer ';

      verifyToken(mockReq, mockRes, nextMock);

      expect(mockRes.status).toHaveBeenCalledWith(401);
    });

    test('devrait extraire correctement les données du payload', () => {
      const payload = { 
        userId: 42, 
        email: 'john.doe@example.com',
        role: 'admin'
      };
      const token = jwt.sign(payload, JWT_SECRET);

      mockReq.headers.authorization = `Bearer ${token}`;

      verifyToken(mockReq, mockRes, nextMock);

      expect(mockReq.userId).toBe(42);
      expect(mockReq.userEmail).toBe('john.doe@example.com');
    });

    test('devrait rejeter un header Authorization avec seulement "Bearer"', () => {
      mockReq.headers.authorization = 'Bearer';

      verifyToken(mockReq, mockRes, nextMock);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Format de token invalide. Utilisez: Bearer <token>'
        })
      );
    });
  });

  describe('optionalAuth', () => {
    test('devrait passer avec un token valide et définir userId', () => {
      const token = jwt.sign(
        { userId: 1, email: 'test@example.com' },
        JWT_SECRET
      );

      mockReq.headers.authorization = `Bearer ${token}`;

      optionalAuth(mockReq, mockRes, nextMock);

      expect(nextMock).toHaveBeenCalled();
      expect(mockReq.userId).toBe(1);
      expect(mockReq.userEmail).toBe('test@example.com');
    });

    test('devrait passer sans token et définir userId à null', () => {
      optionalAuth(mockReq, mockRes, nextMock);

      expect(nextMock).toHaveBeenCalled();
      expect(mockReq.userId).toBeNull();
    });

    test('devrait passer avec un token invalide et définir userId à null', () => {
      mockReq.headers.authorization = 'Bearer invalid-token';

      optionalAuth(mockReq, mockRes, nextMock);

      expect(nextMock).toHaveBeenCalled();
      expect(mockReq.userId).toBeNull();
    });

    test('devrait passer avec un format de token incorrect et définir userId à null', () => {
      const token = jwt.sign({ userId: 1 }, JWT_SECRET);
      mockReq.headers.authorization = token; // Sans "Bearer"

      optionalAuth(mockReq, mockRes, nextMock);

      expect(nextMock).toHaveBeenCalled();
      expect(mockReq.userId).toBeNull();
    });

    test('ne devrait jamais retourner une erreur 401', () => {
      // Test avec différents scénarios
      const scenarios = [
        {}, // Pas de headers
        { headers: {} },
        { headers: { authorization: 'invalid' } },
        { headers: { authorization: 'Bearer invalid.token.here' } }
      ];

      scenarios.forEach(scenario => {
        jest.clearAllMocks();
        const req = { ...mockReq, ...scenario };
        
        optionalAuth(req, mockRes, nextMock);

        expect(mockRes.status).not.toHaveBeenCalledWith(401);
        expect(nextMock).toHaveBeenCalled();
      });
    });
  });

  describe('JWT_SECRET', () => {
    test('devrait utiliser la valeur par défaut si non définie en env', () => {
      const originalEnv = process.env.JWT_SECRET;
      delete process.env.JWT_SECRET;

      // Recharger le module pour obtenir la nouvelle valeur
      jest.resetModules();
      const { JWT_SECRET: newSecret } = require('../middleware/jwt.middleware');
      
      expect(newSecret).toBe('test-secret-key');

      process.env.JWT_SECRET = originalEnv;
    });
  });
});
