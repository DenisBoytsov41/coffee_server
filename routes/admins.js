//const connsql = require('../database');
const pool = require('../pool');
const bcrypt = require('bcrypt');
const {sendMail} = require('../mailer');
const { validateSmen } = require('../validationsmen');

const nameRegex = /^[а-яА-Яa-zA-Z]+(?:[-\s][а-яА-Яa-zA-Z]+)?$/u;
const phoneRegex = /^(\+7|8)?[-. ]?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{2}[-. ]?\d{2}$/;

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

function checkAdminAccess(refreshToken, callback) {
    const tokenQuery = 'SELECT user FROM UserToken WHERE refreshToken = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return callback(err);
        }

        connection.query(tokenQuery, [refreshToken], (err, tokenResult) => {
            if (err) {
                console.error('Ошибка при проверке токена пользователя:', err);
                connection.release();
                return callback(err);
            }

            if (tokenResult.length === 0) {
                connection.release();
                return callback(null, false, 'Недостаточно прав');
            }

            const userLogin = tokenResult[0].user;

            const accessQuery = 'SELECT access_level FROM user_access_rights WHERE login = ?';

            connection.query(accessQuery, [userLogin], (err, accessResult) => {
                connection.release();
                if (err) {
                    console.error('Ошибка при проверке уровня доступа пользователя:', err);
                    return callback(err);
                }

                if (accessResult.length === 0 || accessResult[0].access_level !== 'admin') {
                    return callback(null, false, 'Недостаточно прав');
                }

                return callback(null, true, null, userLogin);
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

    const tokenQuery = 'SELECT user FROM UserToken WHERE refreshToken = ?';

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
                return res.status(403).json({ error: 'Нет данных' });
            }

            const login = tokenResult[0].user;
            updateNewUserDetails({ refreshToken, firstname, lastname, email, gender, phone, login }, res);
        });
    });
}

async function updateNewUserDetails(req, res) {
    console.log(req);
    const { refreshToken, firstname, lastname, email, gender, phone, login } = req;

    checkAdminAccess(refreshToken, async (err) => {
        if (err) {
            return res.status(403).send('Access denied');
        }

        if (gender && gender !== 'Мужской' && gender !== 'Женский') {
            return res.status(400).send('Неверный пол');
        }

        if (firstname && (firstname.length < 2 || !nameRegex.test(firstname))) {
            return res.status(400).send('Неверный firstname');
        }

        if (lastname && (lastname.length < 2 || !nameRegex.test(lastname))) {
            return res.status(400).send('Неверный lastname');
        }

        if (phone && !phoneRegex.test(phone)) {
            return res.status(400).send('Неверный номер телефона');
        }

        const userQuery = 'SELECT * FROM newusers WHERE login = ?';

        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).send('Ошибка сервера');
            }

            connection.query(userQuery, [login], async (err, result) => {
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

                connection.query(updateQuery, values, async (err, result) => {
                    connection.release();

                    if (err) {
                        console.error('Ошибка при обновлении информации пользователя:', err);
                        return res.status(500).send('Ошибка сервера');
                    }

                    // Успешное обновление данных, отправляем уведомление пользователю
                    const theme = 'Уведомление о смене данных';
                    const text = 'Ваши данные были успешно обновлены.';
                    const textHtml = '<p>Ваши данные были успешно обновлены.</p>';

                    try {
                        await sendMail(email, theme, text, textHtml);
                        res.json({ status: 'ok' });
                    } catch (error) {
                        console.error('Ошибка при отправке уведомления:', error);
                        res.status(500).send('Ошибка сервера');
                    }
                });
            });
        });
    });
}



function deleteNewUser(req, res) {
    const { refreshToken, loginToDelete } = req.body;

    if (!refreshToken || !loginToDelete) {
        return res.status(400).json({ error: 'Потеря refreshToken или loginToDelete' });
    }

    checkAdminAccess(refreshToken, (err, isAdmin, errorMsg, currentAdminLogin) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        if (!isAdmin) {
            return res.status(403).json({ error: errorMsg });
        }

        if (loginToDelete === currentAdminLogin) {
            return res.status(403).json({ error: 'Нельзя удалить самого себя' });
        }

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

                const getUserEmailQuery = 'SELECT email FROM newusers WHERE login = ?';
                const deleteUserItemsQuery = 'DELETE FROM usersItems WHERE login = ?';
                const deleteUserTokensQuery = 'DELETE FROM UserToken WHERE user = ?';
                const deleteUserAccessRightsQuery = 'DELETE FROM user_access_rights WHERE login = ?';
                const deleteUserQuery = 'DELETE FROM newusers WHERE login = ?';

                connection.query(getUserEmailQuery, [loginToDelete], (err, result) => {
                    if (err) {
                        console.error('Ошибка при получении электронной почты пользователя:', err);
                        return connection.rollback(() => {
                            connection.release();
                            return res.status(500).json({ error: 'Ошибка сервера' });
                        });
                    }

                    if (result.length === 0) {
                        console.error('Пользователь не найден');
                        return connection.rollback(() => {
                            connection.release();
                            return res.status(404).json({ error: 'Пользователь не найден' });
                        });
                    }

                    const userEmail = result[0].email;

                    connection.query(deleteUserItemsQuery, [loginToDelete], (err) => {
                        if (err) {
                            console.error('Ошибка при удалении items пользователя:', err);
                            return connection.rollback(() => {
                                connection.release();
                                return res.status(500).json({ error: 'Ошибка сервера' });
                            });
                        }

                        connection.query(deleteUserTokensQuery, [loginToDelete], (err) => {
                            if (err) {
                                console.error('Ошибка при удалении токенов пользователя:', err);
                                return connection.rollback(() => {
                                    connection.release();
                                    return res.status(500).json({ error: 'Ошибка сервера' });
                                });
                            }

                            connection.query(deleteUserAccessRightsQuery, [loginToDelete], (err) => {
                                if (err) {
                                    console.error('Ошибка при удалении прав доступа пользователя:', err);
                                    return connection.rollback(() => {
                                        connection.release();
                                        return res.status(500).json({ error: 'Ошибка сервера' });
                                    });
                                }

                                connection.query(deleteUserQuery, [loginToDelete], (err) => {
                                    if (err) {
                                        console.error('Ошибка при удалении пользователя:', err);
                                        return connection.rollback(() => {
                                            connection.release();
                                            return res.status(500).json({ error: 'Ошибка сервера' });
                                        });
                                    }

                                    // Если удаление прошло успешно, отправляем сообщение
                                    const theme = 'Пользователь успешно удален';
                                    const text = 'Ваш аккаунт был успешно удален.';
                                    const textHtml = '<p>Ваш аккаунт был успешно удален.</p>';

                                    sendMail(userEmail, theme, text, textHtml)
                                        .then(() => {
                                            connection.commit((err) => {
                                                if (err) {
                                                    console.error('Ошибка при коммите транзакции:', err);
                                                    return connection.rollback(() => {
                                                        connection.release();
                                                        return res.status(500).json({ error: 'Ошибка сервера' });
                                                    });
                                                }

                                                connection.release();
                                                return res.json({ status: 'ok' }); // Отправка успешного ответа
                                            });
                                        })
                                        .catch((error) => {
                                            console.error('Ошибка при отправке электронной почты:', error);
                                            return connection.rollback(() => {
                                                connection.release();
                                                return res.status(500).json({ error: 'Ошибка сервера' });
                                            });
                                        });
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