const request = require('supertest');
const app = require('./server');

describe('Admin authentication', () => {
    it('should return 400 if refreshToken is not provided', async () => {
        const res = await request(app)
            .post('/checkAdminCredentials')
            .send({ });
        expect(res.statusCode).toEqual(400);
    });

    it('should return 404 if refreshToken is invalid', async () => {
        const res = await request(app)
            .post('/checkAdminCredentials')
            .send({ refreshToken: 'invalidRefreshToken' });
        expect(res.statusCode).toEqual(404);
    });

    it('should return 404 if user does not have admin access', async () => {
        const res = await request(app)
            .post('/checkAdminCredentials')
            .send({ refreshToken: 'validRefreshToken', login: 'regularUser', password: 'password' });
        expect(res.statusCode).toEqual(404);
    });

    it('should return 404 if login or password is incorrect', async () => {
        const res = await request(app)
            .post('/checkAdminCredentials')
            .send({ refreshToken: 'validRefreshToken', login: 'admin', password: 'incorrectPassword' });
        expect(res.statusCode).toEqual(404);
    });

    it('should return 200 if login and password are correct', async () => {
        const res = await request(app)
            .post('/checkAdminCredentials')
            .send({ refreshToken: 'validRefreshToken', login: 'admin', password: 'correctPassword' });
        expect(res.statusCode).toEqual(200);
    });
});
