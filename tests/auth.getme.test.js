// tests/auth.getme.test.js - Tests pour le getMe controller
const { register, getMe, clearUsers } = require('../controllers/auth.controller');

describe('Auth Controller - GetMe', () => {
  let mockReq;
  let mockRes;
  let jsonMock;
  let statusMock;
  let createdUserId;

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

    // Create a test user
    const registerReq = {
      body: {
        email: 'test@example.com',
        password: 'password123',
        username: 'testuser'
      }
    };
    await register(registerReq, mockRes);
    createdUserId = jsonMock.mock.calls[0][0].user.id;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /auth/me', () => {
    test('devrait retourner les informations de l\'utilisateur connecté', () => {
      mockReq = {
        userId: createdUserId
      };

      // Reset mocks after registration
      jest.clearAllMocks();
      statusMock.mockReturnValue({ json: jsonMock });

      getMe(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          user: expect.objectContaining({
            id: createdUserId,
            email: 'test@example.com',
            username: 'testuser'
          })
        })
      );
    });

    test('ne devrait pas retourner le mot de passe dans la réponse', () => {
      mockReq = {
        userId: createdUserId
      };

      jest.clearAllMocks();
      statusMock.mockReturnValue({ json: jsonMock });

      getMe(mockReq, mockRes);

      const response = jsonMock.mock.calls[0][0];
      expect(response.user).toBeDefined();
      expect(response.user.password).toBeUndefined();
    });

    test('devrait retourner 404 si l\'utilisateur n\'existe pas', () => {
      mockReq = {
        userId: 9999 // ID inexistant
      };

      jest.clearAllMocks();
      statusMock.mockReturnValue({ json: jsonMock });

      getMe(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(404);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Utilisateur non trouvé'
        })
      );
    });

    test('devrait retourner 404 si userId est undefined', () => {
      mockReq = {
        userId: undefined
      };

      jest.clearAllMocks();
      statusMock.mockReturnValue({ json: jsonMock });

      getMe(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(404);
    });

    test('devrait retourner 404 si userId est null', () => {
      mockReq = {
        userId: null
      };

      jest.clearAllMocks();
      statusMock.mockReturnValue({ json: jsonMock });

      getMe(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(404);
    });

    test('devrait inclure tous les champs publics de l\'utilisateur', () => {
      mockReq = {
        userId: createdUserId
      };

      jest.clearAllMocks();
      statusMock.mockReturnValue({ json: jsonMock });

      getMe(mockReq, mockRes);

      const response = jsonMock.mock.calls[0][0];
      expect(response.user).toHaveProperty('id');
      expect(response.user).toHaveProperty('email');
      expect(response.user).toHaveProperty('username');
    });

    test('devrait retourner les bonnes informations après création de plusieurs utilisateurs', async () => {
      // Créer un deuxième utilisateur
      jest.clearAllMocks();
      statusMock.mockReturnValue({ json: jsonMock });

      await register({
        body: {
          email: 'second@example.com',
          password: 'password456',
          username: 'seconduser'
        }
      }, mockRes);

      const secondUserId = jsonMock.mock.calls[0][0].user.id;

      // Tester getMe pour le deuxième utilisateur
      jest.clearAllMocks();
      statusMock.mockReturnValue({ json: jsonMock });

      mockReq = {
        userId: secondUserId
      };

      getMe(mockReq, mockRes);

      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          user: expect.objectContaining({
            id: secondUserId,
            email: 'second@example.com',
            username: 'seconduser'
          })
        })
      );
    });
  });
});
