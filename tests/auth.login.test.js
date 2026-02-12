// tests/auth.login.test.js - Tests pour le login controller
const { login, register, clearUsers } = require('../controllers/auth.controller');

describe('Auth Controller - Login', () => {
  let mockReq;
  let mockRes;
  let jsonMock;
  let statusMock;

  beforeEach(async () => {
    // Clear users before each test
    clearUsers();

    // Setup mock response
    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });
    mockRes = {
      status: statusMock,
      json: jsonMock
    };

    // Create a test user for login tests
    const registerReq = {
      body: {
        email: 'test@example.com',
        password: 'password123',
        username: 'testuser'
      }
    };
    await register(registerReq, mockRes);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /auth/login', () => {
    test('devrait connecter un utilisateur avec des identifiants valides', async () => {
      mockReq = {
        body: {
          email: 'test@example.com',
          password: 'password123'
        }
      };

      await login(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Connexion réussie',
          user: expect.objectContaining({
            id: expect.any(Number),
            email: 'test@example.com',
            username: 'testuser'
          }),
          token: expect.any(String)
        })
      );
    });

    test('devrait rejeter une connexion avec email inexistant', async () => {
      mockReq = {
        body: {
          email: 'nonexistent@example.com',
          password: 'password123'
        }
      };

      await login(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Email ou mot de passe incorrect'
        })
      );
    });

    test('devrait rejeter une connexion avec mot de passe incorrect', async () => {
      mockReq = {
        body: {
          email: 'test@example.com',
          password: 'wrongpassword'
        }
      };

      await login(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Email ou mot de passe incorrect'
        })
      );
    });

    test('devrait rejeter une connexion sans email', async () => {
      mockReq = {
        body: {
          password: 'password123'
        }
      };

      await login(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Email et mot de passe requis'
        })
      );
    });

    test('devrait rejeter une connexion sans mot de passe', async () => {
      mockReq = {
        body: {
          email: 'test@example.com'
        }
      };

      await login(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Email et mot de passe requis'
        })
      );
    });

    test('devrait rejeter une connexion avec email et mot de passe vides', async () => {
      mockReq = {
        body: {
          email: '',
          password: ''
        }
      };

      await login(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(400);
    });

    test('devrait retourner un token JWT valide lors de la connexion', async () => {
      mockReq = {
        body: {
          email: 'test@example.com',
          password: 'password123'
        }
      };

      await login(mockReq, mockRes);

      const response = jsonMock.mock.calls[0][0];
      expect(response.token).toBeDefined();
      expect(typeof response.token).toBe('string');
      expect(response.token.split('.')).toHaveLength(3); // JWT structure
    });

    test('ne devrait pas retourner le mot de passe dans la réponse', async () => {
      mockReq = {
        body: {
          email: 'test@example.com',
          password: 'password123'
        }
      };

      await login(mockReq, mockRes);

      const response = jsonMock.mock.calls[0][0];
      expect(response.user).toBeDefined();
      expect(response.user.password).toBeUndefined();
    });

    test('devrait retourner 500 en cas d\'erreur serveur', async () => {
      // Simuler une erreur en modifiant temporairement users.find
      const originalFind = Array.prototype.find;
      Array.prototype.find = jest.fn(() => {
        throw new Error('Database error');
      });

      mockReq = {
        body: {
          email: 'test@example.com',
          password: 'password123'
        }
      };

      await login(mockReq, mockRes);

      // Restaurer find
      Array.prototype.find = originalFind;

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Erreur serveur'
        })
      );
    });
  });
});
