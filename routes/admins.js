//const connsql = require('../database');
const pool = require('../pool');
const bcrypt = require('bcrypt');
const { validateSmen } = require('../validationsmen');

function checkAdminCredentials(req, res) {
    const { login, password, refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: 'Bad Request' });
    }

    const tokenQuery = 'SELECT user FROM UserToken WHERE refreshToken = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        connection.query(tokenQuery, [refreshToken], (err, tokenResult) => {
            if (err) {
                console.error('Ошибка при проверке токена пользователя:', err);
                connection.release();
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (tokenResult.length === 0) {
                connection.release();
                return res.status(403).json({ error: 'Недостаточно прав' });
            }

            const userLogin = tokenResult[0].user;

            const accessQuery = 'SELECT access_level FROM user_access_rights WHERE login = ?';

            connection.query(accessQuery, [userLogin], (err, accessResult) => {
                if (err) {
                    console.error('Ошибка при проверке уровня доступа пользователя:', err);
                    connection.release();
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                if (accessResult.length === 0 || accessResult[0].access_level !== 'admin') {
                    connection.release();
                    return res.status(403).json({ error: 'Недостаточно прав' });
                }

                const adminQuery = 'SELECT password FROM AdminUsers WHERE login = ?';

                connection.query(adminQuery, [login], async (err, result) => {
                    connection.release();

                    if (err) {
                        console.error('Ошибка при выполнении запроса:', err);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    if (result.length === 1) {
                        const hashedPassword = result[0].password;
                        console.log(result);
                        console.log(hashedPassword);
                        console.log(password);
                        console.log(await bcrypt.compare(password, hashedPassword));
                        const match = await bcrypt.compare(password, hashedPassword);
                        if (match) {
                            return res.json({ status: 'ok' });
                        } else {
                            return res.status(403).json({ error: 'Пользователь или пароль введены неверно' });
                        }
                    } else {
                        return res.status(403).json({ error: 'Пользователь или пароль введены неверно' });
                    }
                });
            });
        });
    });
}

function checkAdminCredentialsRefreshToken(req, res) {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: 'Bad Request' });
    }

    const tokenQuery = 'SELECT user FROM UserToken WHERE refreshToken = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        connection.query(tokenQuery, [refreshToken], (err, tokenResult) => {
            if (err) {
                console.error('Ошибка при проверке токена пользователя:', err);
                connection.release();
                return res.status(500).json({ error: 'Ошибка при проверке токена пользователя:' });
            }

            if (tokenResult.length === 0) {
                connection.release();
                return res.status(403).json({ error: 'Недостаточно прав' });
            }

            const userLogin = tokenResult[0].user;

            const accessQuery = 'SELECT access_level FROM user_access_rights WHERE login = ?';

            connection.query(accessQuery, [userLogin], (err, accessResult) => {
                if (err) {
                    console.error('Ошибка при проверке уровня доступа пользователя:', err);
                    connection.release();
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                if (accessResult.length === 0 || accessResult[0].access_level !== 'admin') {
                    connection.release();
                    return res.status(403).json({ error: 'Недостаточно прав' });
                }

                return res.json({ status: 'ok' });
            });
        });
    });
}

async function addUserAdmin(req, res) {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({ error: 'Bad Request' });
    }

    // Проверка длины логина и пароля
    if (login.length < 5 || password.length < 5) {
        return res.status(400).json({ error: 'Логин и пароль должны содержать не менее 5 символов' });
    }

    try {
        const hashedPassword = await hashPassword(password);
    
        const checkUserQuery = 'SELECT COUNT(*) AS count FROM AdminUsers WHERE login = ?';
        
        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            
            connection.query(checkUserQuery, [login], (err, result) => {
                if (err) {
                    connection.release();
                    console.error('Ошибка при выполнении запроса:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }
    
                if (result[0].count > 0) {
                    connection.release();
                    return res.status(400).json({ error: 'Пользователь с таким логином уже существует' });
                }
    
                const addUserQuery = 'INSERT INTO AdminUsers (login, password) VALUES (?, ?)';
                
                connection.query(addUserQuery, [login, hashedPassword], (err) => {
                    connection.release();
    
                    if (err) {
                        console.error('Ошибка при выполнении запроса:', err);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }
    
                    return res.json({ status: 'ok' });
                });
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
    if (newPassword.length < 5) {
        return res.status(400).json({ error: 'Пароль должен содержать не менее 5 символов' });
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

function updateNewUserAdminInfo(req, res) {
    const { firstname, lastname, email, gender, phone, refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: 'Потеря refreshToken' });
    }

    const tokenQuery = 'SELECT login FROM UserToken WHERE refreshToken = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        connection.query(tokenQuery, [refreshToken], (err, tokenResult) => {
            connection.release();

            if (err) {
                console.error('Ошибка при проверке токена пользователя:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (tokenResult.length === 0) {
                return res.status(403).json({ error: 'Недостаточно прав' });
            }

            const login = tokenResult[0].login;
            updateNewUserDetails({ firstname, lastname, email, gender, phone, login }, res);
        });
    });
}

function updateNewUserDetails({ firstname, lastname, email, gender, phone, login }, res) {
    const userQuery = 'SELECT * FROM newusers WHERE login = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(userQuery, [login], (err, result) => {
            if (err) {
                console.error('Ошибка при запросе newusers:', err);
                connection.release();
                return res.status(500).send('Ошибка сервера');
            }

            if (result.length === 0) {
                connection.release();
                return res.status(404).send('Пользователь не найден');
            }

            const user = result[0];
            let updates = [];
            let values = [];

            if (firstname && firstname !== user.firstname) {
                updates.push('firstname = ?');
                values.push(firstname);
            }
            if (lastname && lastname !== user.lastname) {
                updates.push('lastname = ?');
                values.push(lastname);
            }
            if (email && email.toLowerCase() !== user.email) {
                updates.push('email = ?');
                values.push(email.toLowerCase());
            }
            if (gender && gender !== user.gender) {
                updates.push('gender = ?');
                values.push(gender);
            }
            if (phone && phone !== user.phone) {
                updates.push('phone = ?');
                values.push(phone);
            }

            if (updates.length === 0) {
                connection.release();
                return res.json({ status: 'Успешная смена данных' });
            }

            values.push(login);

            const updateQuery = `UPDATE newusers SET ${updates.join(', ')} WHERE login = ?`;

            connection.query(updateQuery, values, (err, result) => {
                connection.release();

                if (err) {
                    console.error('Ошибка при обновлении информации пользователя:', err);
                    return res.status(500).send('Ошибка сервера');
                }

                res.json({ status: 'ok' });
            });
        });
    });
}

function deleteNewUser(req, res) {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: 'Потеря refreshToken' });
    }

    const tokenQuery = 'SELECT login FROM UserToken WHERE refreshToken = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        connection.beginTransaction((err) => {
            if (err) {
                console.error('Ошибка при начале транзакции:', err);
                connection.release();
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            connection.query(tokenQuery, [refreshToken], (err, tokenResult) => {
                if (err) {
                    console.error('Ошибка при проверке токена пользователя:', err);
                    return connection.rollback(() => {
                        connection.release();
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    });
                }

                if (tokenResult.length === 0) {
                    connection.release();
                    return res.status(403).json({ error: 'Недостаточно прав' });
                }

                const login = tokenResult[0].login;

                const deleteUserItemsQuery = 'DELETE FROM usersItems WHERE user = ?';
                const deleteUserTokensQuery = 'DELETE FROM UserToken WHERE login = ?';
                const deleteUserAccessRightsQuery = 'DELETE FROM user_access_rights WHERE login = ?';
                const deleteUserQuery = 'DELETE FROM newusers WHERE login = ?';

                connection.query(deleteUserItemsQuery, [login], (err) => {
                    if (err) {
                        console.error('Ошибка при удалении items пользователя:', err);
                        return connection.rollback(() => {
                            connection.release();
                            return res.status(500).json({ error: 'Ошибка сервера' });
                        });
                    }

                    connection.query(deleteUserTokensQuery, [login], (err) => {
                        if (err) {
                            console.error('Ошибка при удалении токенов пользователя:', err);
                            return connection.rollback(() => {
                                connection.release();
                                return res.status(500).json({ error: 'Ошибка сервера' });
                            });
                        }

                        connection.query(deleteUserAccessRightsQuery, [login], (err) => {
                            if (err) {
                                console.error('Ошибка при удалении прав доступа пользователя:', err);
                                return connection.rollback(() => {
                                    connection.release();
                                    return res.status(500).json({ error: 'Ошибка сервера' });
                                });
                            }

                            connection.query(deleteUserQuery, [login], (err) => {
                                if (err) {
                                    console.error('Ошибка при удалении пользователя:', err);
                                    return connection.rollback(() => {
                                        connection.release();
                                        return res.status(500).json({ error: 'Ошибка сервера' });
                                    });
                                }

                                connection.commit((err) => {
                                    if (err) {
                                        console.error('Ошибка при коммите транзакции:', err);
                                        return connection.rollback(() => {
                                            connection.release();
                                            return res.status(500).json({ error: 'Ошибка сервера' });
                                        });
                                    }

                                    connection.release();
                                    return res.json({ status: 'ok' });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
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
    deleteAdminUser,
    updateNewUserAdminInfo,
    deleteNewUser,
    checkAdminCredentialsRefreshToken
};