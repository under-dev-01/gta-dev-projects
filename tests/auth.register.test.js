// tests/auth.register.test.js - Tests pour le register controller
const { register, clearUsers, users } = require('../controllers/auth.controller');

describe('Auth Controller - Register', () => {
  let mockReq;
  let mockRes;
  let jsonMock;
  let statusMock;

  beforeEach(() => {
    // Clear users before each test
    clearUsers();

    // Setup mock response
    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });
    mockRes = {
      status: statusMock,
      json: jsonMock
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /auth/register', () => {
    test('devrait créer un nouvel utilisateur avec des données valides', async () => {
      mockReq = {
        body: {
          email: 'user@example.com',
          password: 'password123',
          username: 'newuser'
        }
      };

      await register(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(201);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Utilisateur créé avec succès',
          user: expect.objectContaining({
            id: expect.any(Number),
            email: 'user@example.com',
            username: 'newuser'
          }),
          token: expect.any(String)
        })
      );
    });

    test('devrait hasher le mot de passe avant de stocker', async () => {
      mockReq = {
        body: {
          email: 'user@example.com',
          password: 'password123',
          username: 'newuser'
        }
      };

      await register(mockReq, mockRes);

      // Vérifier que le mot de passe stocké est différent du mot de passe en clair
      const storedUser = users.find(u => u.email === 'user@example.com');
      expect(storedUser.password).not.toBe('password123');
      expect(storedUser.password).toMatch(/^\$2[aby]\$\d+\$/); // Format bcrypt
    });

    test('devrait rejeter un email déjà utilisé', async () => {
      // Créer un premier utilisateur
      await register({
        body: {
          email: 'existing@example.com',
          password: 'password123',
          username: 'existinguser'
        }
      }, mockRes);

      jest.clearAllMocks();
      statusMock.mockReturnValue({ json: jsonMock });

      // Essayer de créer un utilisateur avec le même email
      mockReq = {
        body: {
          email: 'existing@example.com',
          password: 'different123',
          username: 'differentuser'
        }
      };

      await register(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(409);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Cet email est déjà utilisé'
        })
      );
    });

    test('devrait rejeter un email invalide', async () => {
      mockReq = {
        body: {
          email: 'invalid-email',
          password: 'password123',
          username: 'newuser'
        }
      };

      await register(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Format email invalide'
        })
      );
    });

    test('devrait rejeter un mot de passe trop court', async () => {
      mockReq = {
        body: {
          email: 'user@example.com',
          password: '123',
          username: 'newuser'
        }
      };

      await register(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Le mot de passe doit contenir au moins 6 caractères'
        })
      );
    });

    test('devrait rejeter une requête sans email', async () => {
      mockReq = {
        body: {
          password: 'password123',
          username: 'newuser'
        }
      };

      await register(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Tous les champs sont requis: email, password, username'
        })
      );
    });

    test('devrait rejeter une requête sans mot de passe', async () => {
      mockReq = {
        body: {
          email: 'user@example.com',
          username: 'newuser'
        }
      };

      await register(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Tous les champs sont requis: email, password, username'
        })
      );
    });

    test('devrait rejeter une requête sans username', async () => {
      mockReq = {
        body: {
          email: 'user@example.com',
          password: 'password123'
        }
      };

      await register(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Tous les champs sont requis: email, password, username'
        })
      );
    });

    test('devrait retourner un token JWT après inscription', async () => {
      mockReq = {
        body: {
          email: 'user@example.com',
          password: 'password123',
          username: 'newuser'
        }
      };

      await register(mockReq, mockRes);

      const response = jsonMock.mock.calls[0][0];
      expect(response.token).toBeDefined();
      expect(typeof response.token).toBe('string');
      expect(response.token.split('.')).toHaveLength(3); // Structure JWT
    });

    test('ne devrait pas retourner le mot de passe dans la réponse', async () => {
      mockReq = {
        body: {
          email: 'user@example.com',
          password: 'password123',
          username: 'newuser'
        }
      };

      await register(mockReq, mockRes);

      const response = jsonMock.mock.calls[0][0];
      expect(response.user).toBeDefined();
      expect(response.user.password).toBeUndefined();
    });

    test('devrait accepter différents formats d\'email valides', async () => {
      const validEmails = [
        'user@example.com',
        'user.name@example.com',
        'user+tag@example.com',
        'user@sub.example.com'
      ];

      for (let i = 0; i < validEmails.length; i++) {
        clearUsers();
        jest.clearAllMocks();
        statusMock.mockReturnValue({ json: jsonMock });

        mockReq = {
          body: {
            email: validEmails[i],
            password: 'password123',
            username: `user${i}`
          }
        };

        await register(mockReq, mockRes);

        expect(statusMock).toHaveBeenCalledWith(201);
      }
    });

    test('devrait assigner un ID unique à chaque utilisateur', async () => {
      const createdIds = [];

      for (let i = 0; i < 3; i++) {
        // Ne pas clear pour ce test - on veut des IDs incrémentaux
        jest.clearAllMocks();
        statusMock.mockReturnValue({ json: jsonMock });

        await register({
          body: {
            email: `user${i}@example.com`,
            password: 'password123',
            username: `user${i}`
          }
        }, mockRes);

        const response = jsonMock.mock.calls[0][0];
        createdIds.push(response.user.id);
      }

      // Les IDs devraient être uniques et incrémentaux (1, 2, 3)
      const uniqueIds = [...new Set(createdIds)];
      expect(uniqueIds.length).toBe(3);
      expect(createdIds).toEqual([1, 2, 3]);
    });
  });
});
