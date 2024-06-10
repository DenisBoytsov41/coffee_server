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

function deleteOrder(req, res) {
    const { refreshToken, orderIdToDelete } = req.body;

    if (!refreshToken || !orderIdToDelete) {
        return res.status(400).json({ error: 'Потеря refreshToken или orderIdToDelete' });
    }

    checkAdminAccess(refreshToken, (err, isAdmin, errorMsg, currentAdminLogin) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        if (!isAdmin) {
            return res.status(403).json({ error: errorMsg });
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

                const deleteOrderQuery = 'DELETE FROM OrderHistory WHERE id = ?';

                connection.query(deleteOrderQuery, [orderIdToDelete], (err, result) => {
                    if (err) {
                        console.error('Ошибка при удалении заказа:', err);
                        return connection.rollback(() => {
                            connection.release();
                            return res.status(500).json({ error: 'Ошибка сервера' });
                        });
                    }

                    if (result.affectedRows === 0) {
                        console.error('Заказ с указанным id не найден');
                        return connection.rollback(() => {
                            connection.release();
                            return res.status(404).json({ error: 'Заказ с указанным id не найден' });
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
}
function updateOrder(req, res) {
    const { refreshToken, id, status } = req.body;

    if (!refreshToken || !id || !status) {
        return res.status(400).json({ error: 'Потеря refreshToken, id или status' });
    }

    const validStatuses = ['В обработке', 'Оплачен', 'Отменен', 'Доставлен'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Недопустимый статус' });
    }

    checkAdminAccess(refreshToken, (err, isAdmin, errorMsg, currentAdminLogin) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        if (!isAdmin) {
            return res.status(403).json({ error: errorMsg });
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

                const updateOrderQuery = 'UPDATE OrderHistory SET status = ? WHERE id = ?';

                connection.query(updateOrderQuery, [status, id], async (err, result) => {
                    if (err) {
                        console.error('Ошибка при обновлении информации о заказе:', err);
                        return connection.rollback(() => {
                            connection.release();
                            return res.status(500).json({ error: 'Ошибка сервера' });
                        });
                    }

                    const getOrderNumberQuery = 'SELECT orderId FROM OrderHistory WHERE id = ?';
                    connection.query(getOrderNumberQuery, [id], async (err, orderResult) => {
                        if (err || orderResult.length === 0) {
                            console.error('Ошибка при получении номера заказа:', err);
                            return connection.rollback(() => {
                                connection.release();
                                return res.status(500).json({ error: 'Ошибка сервера' });
                            });
                        }

                        const orderId = orderResult[0].orderId;

                        const getUserEmailQuery = 'SELECT email FROM newusers WHERE login = (SELECT login FROM OrderHistory WHERE id = ?)';
                        connection.query(getUserEmailQuery, [id], async (err, result) => {
                            if (err || result.length === 0) {
                                console.error('Ошибка при получении электронной почты пользователя:', err);
                                // В случае ошибки или если пользователь не найден, используем логин
                                const userLoginQuery = 'SELECT login FROM OrderHistory WHERE id = ?';
                                connection.query(userLoginQuery, [id], async (err, result) => {
                                    if (err || result.length === 0) {
                                        console.error('Ошибка при получении логина пользователя:', err);
                                        return connection.rollback(() => {
                                            connection.release();
                                            return res.status(500).json({ error: 'Ошибка сервера' });
                                        });
                                    }
                                    
                                    const userLogin = result[0].login;
                                    const theme = 'Изменение статуса заказа';
                                    const text = `Статус вашего заказа с номером ${orderId} и почтой ${userLogin} был изменен на: ${status}`;
                                    const textHtml = `<p>Статус вашего заказа с номером <strong>${orderId}</strong> и почтой <strong>${userLogin}</strong> был изменен на: <strong>${status}</strong></p>`;

                                    try {
                                        await sendMail(userLogin, theme, text, textHtml);
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
                                    } catch (error) {
                                        console.error('Ошибка при отправке уведомления:', error);
                                        return connection.rollback(() => {
                                            connection.release();
                                            return res.status(500).json({ error: 'Ошибка сервера' });
                                        });
                                    }
                                });
                            } else {
                                const userEmail = result[0].email;

                                // Успешное обновление данных, отправляем уведомление пользователю
                                const theme = 'Изменение статуса заказа';
                                const text = `Статус вашего заказа с номером ${orderId} был изменен на: ${status}`;
                                const textHtml = `<p>Статус вашего заказа с номером <strong>${orderId}</strong> был изменен на: <strong>${status}</strong></p>`;

                                try {
                                    await sendMail(userEmail, theme, text, textHtml);
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
                                } catch (error) {
                                    console.error('Ошибка при отправке уведомления:', error);
                                    return connection.rollback(() => {
                                        connection.release();
                                        return res.status(500).json({ error: 'Ошибка сервера' });
                                    });
                                }
                            }
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
    checkAdminCredentialsRefreshToken,
    deleteOrder,
    updateOrder
};