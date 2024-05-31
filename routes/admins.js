//const connsql = require('../database');
const pool = require('../pool');
const crypto = require('crypto');
const uuid = require('uuid');

function checkAdminCredentials(req, res) {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({ error: 'Bad Request' });
    }

    const adminQuery = 'SELECT COUNT(*) AS count FROM AdminUsers WHERE login = ? AND password = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        connection.query(adminQuery, [login, password], (err, result) => {
            connection.release();

            if (err) {
                console.error('Ошибка при выполнении запроса:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (result[0].count === 1) {
                return res.json({ status: 'ok' });
            } else {
                return res.status(403).json({ error: 'Пользователь или пароль введены неверно' });
            }
        });
    });
}
async function addUserAdmin(req, res) {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({ error: 'Bad Request' });
    }

    // Проверка длины логина и пароля
    if (login.length < 6 || password.length < 6) {
        return res.status(400).json({ error: 'Логин и пароль должны содержать не менее 6 символов' });
    }

    try {
        const hashedPassword = await hashPassword(password);

        const addUserQuery = 'INSERT INTO AdminUsers (login, password) VALUES (?, ?)';

        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            connection.query(addUserQuery, [login, hashedPassword], (err) => {
                connection.release();

                if (err) {
                    console.error('Ошибка при выполнении запроса:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                return res.json({ status: 'ok' });
            });
        });
    } catch (error) {
        console.error('Ошибка при добавлении пользователя: ', error);
        return res.status(500).json({ error: 'Ошибка сервера' });
    }
}

async function updateUserAdmin(req, res) {
    const { login, newPassword } = req.body;

    if (!login || !newPassword) {
        return res.status(400).json({ error: 'Bad Request' });
    }

    // Проверка длины пароля
    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Пароль должен содержать не менее 6 символов' });
    }

    try {
        const hashedPassword = await hashPassword(newPassword);
        const updateUserQuery = 'UPDATE AdminUsers SET password = ? WHERE login = ?';

        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            connection.query(updateUserQuery, [hashedPassword, login], (err) => {
                connection.release();

                if (err) {
                    console.error('Ошибка при выполнении запроса:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                return res.json({ status: 'ok' });
            });
        });
    } catch (error) {
        console.error('Ошибка при обновлении пользователя: ', error);
        return res.status(500).json({ error: 'Ошибка сервера' });
    }
}

async function deleteAdminUser(req, res) {
    const { login } = req.body;

    if (!login) {
        return res.status(400).json({ error: 'Bad Request' });
    }

    try {
        const deleteUserQuery = 'DELETE FROM AdminUsers WHERE login = ?';

        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            connection.query(deleteUserQuery, [login], (err) => {
                connection.release();

                if (err) {
                    console.error('Ошибка при выполнении запроса:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                return res.json({ status: 'ok' });
            });
        });
    } catch (error) {
        console.error('Ошибка при удалении пользователя: ', error);
        return res.status(500).json({ error: 'Ошибка сервера' });
    }
}
const hashPassword = async (password) => {
    try {
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      return hashedPassword;
    } catch (error) {
      console.error('Ошибка при хешировании пароля: ', error);
      throw error;
    }
  };
module.exports = {
    checkAdminCredentials,
    addUserAdmin,
    updateUserAdmin,
    deleteAdminUser
};