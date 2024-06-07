const md5 = require('md5');
//const connsql = require('../database');
const pool = require('../pool');
const { sendMail } = require('../mailer');
const { validateSmen } = require('../validationsmen');
const crypto = require('crypto');
const {validatePassword} = require('../validatePassword');
const uuid = require('uuid');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');

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

function getNewUsers(req, res) {
    console.log(req.body);
    const query = 'SELECT * FROM newusers';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(query, (err, result) => {
            connection.release();
            if (err) {
                console.error('Ошибка при выполнении запроса к базе данных:', err);
                return res.status(500).send('Ошибка сервера');
            }

            console.log("Данные о пользователях получены успешно");
            res.json(result);
        });
    });
}

function getOrderHistoryAdmin(req, res) {
    console.log(req.body);
    const query = 'SELECT * FROM OrderHistory';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(query, (err, result) => {
            connection.release();
            if (err) {
                console.error('Ошибка при выполнении запроса к базе данных:', err);
                return res.status(500).send('Ошибка сервера');
            }

            console.log("Данные о заказах получены успешно");
            res.json(result);
        });
    });
}


function getUserAccessRights(req, res) {
    console.log(req.body);
    const query = 'SELECT * FROM user_access_rights';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(query, (err, result) => {
            connection.release();
            if (err) {
                console.error('Ошибка при выполнении запроса к базе данных:', err);
                return res.status(500).send('Ошибка сервера');
            }

            console.log("Данные о правах доступа пользователей получены успешно");
            res.json(result);
        });
    });
}
function updateUserAccessLevel(req, res) {
    const { refreshToken, login, access_level } = req.body;

    if (!refreshToken || !login || !access_level) {
        return res.status(400).send('Bad Request');
    }

    if (access_level !== 'admin' && access_level !== 'member') {
        return res.status(400).send('Неверный уровень доступа');
    }

    checkAdminAccess(refreshToken, (err, isAdmin, errorMsg, currentAdminLogin) => {
        if (err) {
            return res.status(500).send('Ошибка сервера');
        }

        if (!isAdmin) {
            return res.status(403).send(errorMsg);
        }

        if (login === currentAdminLogin) {
            return res.status(403).send('Нельзя изменить собственный уровень доступа');
        }

        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).send('Ошибка сервера');
            }

            // Параметризованный запрос для обновления уровня доступа
            const updateQuery = 'UPDATE user_access_rights SET access_level = ? WHERE login = ?';
            connection.query(updateQuery, [access_level, login], (err) => {
                connection.release();
                if (err) {
                    console.error('Ошибка при обновлении уровня доступа:', err);
                    return res.status(500).send('Ошибка сервера');
                }
                res.json({ status: "ok" });
            });
        });
    });
}


// Получить информацию о пользователе
function getInfoUser(req, res) {
  const { loginOrEmail, pass } = req.body;
  
  // Проверка является ли ввод email или логином
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(loginOrEmail);
  const query = isEmail 
      ? 'SELECT name, mail, tel FROM newusers WHERE mail = ? AND password = ?' 
      : 'SELECT name, mail, tel FROM newusers WHERE login = ? AND password = ?';
  
  pool.getConnection((err, connection) => {
      if (err) {
          console.error('Error during getConnection:', err);
          return res.status(500).send('Server error');
      }
      
      const identifier = loginOrEmail.toLowerCase();
      const hashedPassword = md5(pass);

      connection.query(query, [identifier, hashedPassword], (err, result) => {
          connection.release();
          if (err) {
              console.error('Error during getInfoUser:', err);
              return res.status(500).send('Server error');
          }
          
          if (result.length === 0) {
              return res.status(404).send('User not found');
          }

          res.json(result[0]);
      });
  });
}
// Обновить информацию о пользователе
function updateInfoUser(req, res) {
    const { firstname, lastname, email, gender, phone, refreshToken } = req.body;
    const validationResult = validateSmen(req.body);
  
    console.log(req.body);
  
    if (!validationResult.success) {
      return res.status(402).json({ error: validationResult.errors });
    }
  
    if (!refreshToken) {
      return res.status(400).json({ error: ['Потеря refreshToken'] });
    }
  
    // Запрос для получения логина пользователя по refreshToken
    let queryGetLogin = 'SELECT user FROM UserToken WHERE refreshToken = ?';
  
    pool.getConnection((err, connection) => {
      if (err) {
        console.error('Ошибка при получении соединения из пула:', err);
        return res.status(500).send('Ошибка сервера');
      }
  
      connection.query(queryGetLogin, [refreshToken], (err, result) => {
        connection.release();
  
        if (err) {
          console.error('Ошибка при запросе UserToken:', err);
          return res.status(500).send('Ошибка сервера');
        }
  
        if (result.length === 0) {
          console.log(result);
          console.log(refreshToken);
          return res.status(404).send('Пользователь не найден');
        }
        console.log(result);
        const login = result[0].user;
        // Запрос для получения информации о пользователе по логину
        let queryGetUser = 'SELECT * FROM newusers WHERE login = ?';
  
        pool.getConnection((err, connection) => {
          if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
          }
  
          connection.query(queryGetUser, [login], (err, result) => {
            connection.release();
  
            if (err) {
              console.error('Ошибка при запросе newusers:', err);
              return res.status(500).send('Ошибка сервера');
            }
  
            if (result.length === 0) {
              console.log(result);
              console.log(login);
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
  
            // Если нет изменений, возвращаем статус OK
            if (updates.length === 0) {
              return res.json({ status: 'Успешная смена данных' });
            }
  
            values.push(login);
  
            let updateQuery = `UPDATE newusers SET ${updates.join(', ')} WHERE login = ?`;
  
            pool.getConnection((err, connection) => {
              if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).send('Ошибка сервера');
              }
  
              connection.query(updateQuery, values, (err, result) => {
                if (err) {
                  console.error('Ошибка при запросе user info:', err);
                  connection.release();
                  return res.status(500).send('Ошибка сервера');
                }
  
                // Отправляем сообщение после успешного обновления данных пользователя
                const theme = 'Обновление данных профиля';
                const text = 'Ваши данные профиля были успешно обновлены. Если это делали не вы, то обратитесь к администратору на сайте.';
                const textHtml = '<p>Ваши данные профиля были успешно обновлены.  Если это делали не вы, то обратитесь к администратору на сайте.</p>';
  
                sendMail(user.email, theme, text, textHtml)
                  .then(() => {
                    connection.release();
                    res.json({ status: 'ok' });
                  })
                  .catch((error) => {
                    console.error('Ошибка при отправке электронной почты:', error);
                    connection.release();
                    res.status(500).send('Ошибка сервера');
                  });
              });
            });
          });
        });
      });
    });
  }


function checkLoginExistence(req, res) {
    const login = req.body.login; // Получаем логин из тела запроса

    const selectQuery = 'SELECT COUNT(*) AS count FROM newusers WHERE login = ?';
    const selectResetAttemptsQuery = 'SELECT reset_attempts, last_reset_attempt FROM password_reset_attempts WHERE login = ?';
    const updateResetAttemptsQuery = 'UPDATE password_reset_attempts SET reset_attempts = ?, last_reset_attempt = NOW() WHERE login = ?';

    pool.getConnection((err, connection) => {
        if (err) {
        console.error('Ошибка при получении соединения из пула:', err);
        return res.status(500).json({ error: 'Ошибка сервера' });
        }

        connection.query(selectQuery, [login], (err, result) => {
            if (err) {
                connection.release(); // Освобождаем соединение после выполнения запроса
                console.error('Ошибка при проверке существования логина:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            const count = result && result.length > 0 ? result[0].count : 0;
            if (count > 0) {
                connection.query(selectResetAttemptsQuery, [login], (err, resetResult) => {
                if (err) {
                    connection.release(); // Освобождаем соединение после выполнения запроса
                    console.error('Ошибка при проверке попыток сброса пароля:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                const resetAttempts = resetResult && resetResult.length > 0 ? resetResult[0].reset_attempts : 0;
                const lastResetAttempt = resetResult && resetResult.length > 0 ? new Date(resetResult[0].last_reset_attempt) : null;

                if (resetAttempts >= 5) {
                    const currentTime = new Date();
                    const timeDifference = (currentTime - lastResetAttempt) / (1000 * 60); // Разница в минутах
                    if (timeDifference < 15) {
                        connection.release();
                        return res.status(403).json({ error: 'Превышено количество попыток сброса пароля. Попробуйте позже.' });
                    }
                }

                connection.query(updateResetAttemptsQuery, [resetAttempts + 1, login], (err) => {
                    connection.release();
                    if (err) {
                        console.error('Ошибка при обновлении попыток сброса пароля:', err);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    res.json({ exists: true });
                });
            });
            } else {
                connection.release(); // Освобождаем соединение после выполнения запроса
                res.status(404).json({ exists: false, message: 'Логин не найден' });
            }
        });
    });
}

// Отправить письмо для сброса пароля
function sendMailReset(req, res) {
    console.log(req.body);
    if (!req.body || !req.body.email) {
        return res.status(400).json({ error: 'Отсутствует поле "email" в теле запроса' });
    }

    const email = req.body.email.toLowerCase(); // Нормализуем электронную почту
    const uniqueKey = uuid.v4();

    const selectQuery = 'SELECT login, password FROM newusers WHERE email = ?';
    const selectResetAttemptsQuery = 'SELECT reset_attempts, last_reset_attempt FROM password_reset_attempts WHERE login = ?';
    const insertQuery = 'INSERT INTO password_reset_attempts (reset_attempts, login, last_reset_attempt) VALUES (?, ?, NOW())';
    const updateQuery = 'UPDATE password_reset_attempts SET reset_attempts = ?, last_reset_attempt = NOW() WHERE login = ?';
    const resetInsertQuery = "INSERT INTO reset (url) VALUES (?)";

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(selectQuery, [email], (err, result) => {
            if (err) {
                connection.release();
                console.error('Ошибка при запросе пользователя:', err);
                return res.status(500).send('Ошибка сервера');
            }

            if (result && result.length > 0) {
                const login = result[0].login;
                const password = result[0].password;

                connection.query(selectResetAttemptsQuery, [login], (err, resetResult) => {
                    if (err) {
                        connection.release();
                        console.error('Ошибка при проверке попыток сброса пароля:', err);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    const resetAttempts = resetResult && resetResult.length > 0 ? resetResult[0].reset_attempts : 0;
                    const lastResetAttempt = resetResult && resetResult.length > 0 ? new Date(resetResult[0].last_reset_attempt) : null;

                    if (resetAttempts >= 5) {
                        const currentTime = new Date();
                        const timeDifference = (currentTime - lastResetAttempt) / (1000 * 60); // Разница в минутах
                        if (timeDifference < 15) {
                            connection.release();
                            return res.status(403).json({ error: 'Превышено количество попыток сброса пароля. Попробуйте позже.' });
                        } else {
                            // Если прошло более 15 минут, обнуляем количество попыток сброса пароля
                            connection.query(updateQuery, [0, login], (err) => {
                                if (err) {
                                    connection.release();
                                    console.error('Ошибка при обнулении количества попыток сброса пароля:', err);
                                    return res.status(500).send('Ошибка сервера');
                                }
                            });
                        }
                    }

                    const newResetAttempts = resetResult.length === 0 ? 1 : resetAttempts + 1;
                    const resetAttemptsQuery = resetResult.length === 0 ? insertQuery : updateQuery;

                    connection.query(resetAttemptsQuery, [newResetAttempts, login], (err) => {
                        if (err && err.code !== 'ER_DUP_ENTRY') { // Если ошибка не связана с дублированием записи
                            connection.release();
                            console.error('Ошибка при создании или обновлении записи в таблице password_reset_attempts:', err);
                            return res.status(500).send('Ошибка сервера');
                        }

                        const encodedPassword = encodeURIComponent(password); // Кодируем полученный пароль
                        const resetURL = `http://localhost:3000/resetURL/${email}/${encodedPassword}`;
                        const emailSubject = 'Восстановление пароля';
                        const emailBody = 'Это сообщение отправлено для восстановления пароля.';
                        const emailHtml = `<a href=${resetURL}>Перейдите по ссылке для восстановления пароля</a>`;

                        connection.query(resetInsertQuery, [`${resetURL}/${uniqueKey}`], async (err) => {
                            if (err) {
                                connection.release();
                                console.error('Ошибка при добавлении URL для сброса пароля:', err);
                                return res.status(500).send('Ошибка сервера');
                            }

                            try {
                                await sendMail(email, emailSubject, emailBody, emailHtml);
                                res.json({ status: "ok" });
                                connection.release();
                            } catch (error) {
                                console.error('Ошибка при отправке письма:', error);
                                res.status(500).send('Ошибка сервера');
                            }
                        });
                    });
                });
            } else {
                connection.release();
                res.status(404).send('Пользователь не найден');
            }
        });
    });
}

  
function sendNumberReset(req, res) {
    const { login, phone } = req.query;
    console.log(req);
    console.log(req.query);

    if (!login || !phone) {
        return res.status(400).json({ error: 'Отсутствует поле "login" или "phone" в параметрах запроса' });
    }

    const uniqueKey = uuidv4();
    const selectQuery = 'SELECT email, password FROM newusers WHERE login = ?';
    const selectResetAttemptsQuery = 'SELECT reset_attempts, last_reset_attempt FROM password_reset_attempts WHERE login = ?';
    const insertQuery = 'INSERT INTO password_reset_attempts (reset_attempts, login, last_reset_attempt) VALUES (?, ?, NOW())';
    const updateQuery = 'UPDATE password_reset_attempts SET reset_attempts = ?, last_reset_attempt = NOW() WHERE login = ?';
    const resetInsertQuery = "INSERT INTO reset (url) VALUES (?)";

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(selectQuery, [login], (err, results) => {
            if (err) {
                connection.release();
                console.error('Ошибка при запросе пользователя:', err);
                return res.status(500).send('Ошибка сервера');
            }

            if (results.length === 0) {
                connection.release();
                return res.status(404).send('Пользователь не найден');
            }

            const { email, password } = results[0];
            const normalizedEmail = email.toLowerCase();
            const encodedPassword = encodeURIComponent(password);
            const resetURL = `http://localhost:3000/resetURL/${normalizedEmail}/${encodedPassword}`;

            connection.query(selectResetAttemptsQuery, [login], (err, resetResults) => {
                if (err) {
                    connection.release();
                    console.error('Ошибка при проверке попыток сброса пароля:', err);
                    return res.status(500).send('Ошибка сервера');
                }

                const resetAttempts = resetResults && resetResults.length > 0 ? resetResults[0].reset_attempts : 0;
                const lastResetAttempt = resetResults && resetResults.length > 0 ? new Date(resetResults[0].last_reset_attempt) : null;

                if (resetAttempts >= 5) {
                    const currentTime = new Date();
                    const timeDifference = (currentTime - lastResetAttempt) / (1000 * 60); // Разница в минутах
                    if (timeDifference < 15) {
                        connection.release();
                        return res.status(403).json({ error: 'Превышено количество попыток сброса пароля. Попробуйте позже.' });
                    } else {
                        // Если прошло более 15 минут, обнуляем количество попыток сброса пароля
                        connection.query(updateQuery, [0, login], (err) => {
                            if (err) {
                                connection.release();
                                console.error('Ошибка при обнулении количества попыток сброса пароля:', err);
                                return res.status(500).send('Ошибка сервера');
                            }
                        });
                    }
                }

                const newResetAttempts = resetResults.length === 0 ? 1 : resetAttempts + 1;
                const resetAttemptsQuery = resetResults.length === 0 ? insertQuery : updateQuery;

                connection.query(resetAttemptsQuery, [newResetAttempts, login], (err) => {
                    if (err && err.code !== 'ER_DUP_ENTRY') {
                        connection.release();
                        console.error('Ошибка при создании или обновлении записи в таблице password_reset_attempts:', err);
                        return res.status(500).send('Ошибка сервера');
                    }

                    connection.query(resetInsertQuery, [`${resetURL}/${uniqueKey}`], (err) => {
                        connection.release();

                        if (err) {
                            console.error('Ошибка при добавлении URL для сброса пароля:', err);
                            return res.status(500).send('Ошибка сервера');
                        }

                        res.json({ resetURL });
                    });
                });
            });
        });
    });
}


function comparePhoneNumberAndLogin(req, res) {
    const phone = req.body.phone.replace(/\s|\(|\)/g, ''); // Обработка номера телефона
    const login = req.body.login.toLowerCase(); // Нормализация логина

    const selectQuery = 'SELECT phone FROM newusers WHERE login = ?';
    const selectResetAttemptsQuery = 'SELECT reset_attempts, last_reset_attempt FROM password_reset_attempts WHERE login = ?';

    pool.getConnection((err, connection) => {
        if (err) {
        console.error('Ошибка при получении соединения из пула:', err);
        return res.status(500).send('Ошибка сервера');
        }

        connection.query(selectResetAttemptsQuery, [login], (err, resetResult) => {
        if (err) {
            connection.release(); // Освобождаем соединение после выполнения запроса
            console.error('Ошибка при проверке попыток сброса пароля:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        const resetAttempts = resetResult && resetResult.length > 0 ? resetResult[0].reset_attempts : 0;
        const lastResetAttempt = resetResult && resetResult.length > 0 ? new Date(resetResult[0].last_reset_attempt) : null;

        if (resetAttempts >= 5) {
            const currentTime = new Date();
            const timeDifference = (currentTime - lastResetAttempt) / (1000 * 60); // Разница в минутах
            if (timeDifference < 15) {
            connection.release(); // Освобождаем соединение после выполнения запроса
            return res.status(403).json({ error: 'Превышено количество попыток сброса пароля. Попробуйте позже.' });
            }
        }

        connection.query(selectQuery, [login], (err, result) => {
            if (err) {
            connection.release(); // Освобождаем соединение после выполнения запроса
            console.error('Ошибка при запросе номера телефона пользователя:', err);
            return res.status(500).send('Ошибка сервера');
            }

            if (result && result.length > 0) {
            const { phone: userPhone } = result[0];
            const formattedUserPhone = userPhone.replace(/\s|\(|\)/g, ''); // Обработка номера телефона из базы данных

            if (formattedUserPhone === phone) {
                res.json({ match: true });
            } else {
                res.json({ match: false });
            }
            } else {
            res.status(404).send('Пользователь не найден');
            }
            connection.release(); // Освобождаем соединение после выполнения запроса
        });
        });
    });
}
  
  
async function resetPassword(req, res) {
    const { email, token, password, confirmPassword } = req.body;
    console.log(req.body);

    if (!email || !token || !password || !confirmPassword) {
        return res.status(400).json({ error: 'Отсутствуют обязательные поля' });
    }
    // Запрос для получения логина и текущего хешированного пароля пользователя
    const selectQuery = 'SELECT login, password FROM newusers WHERE email = ?';
    const query = 'SELECT reset_attempts, last_reset_attempt FROM password_reset_attempts WHERE login = ?';
    const updateQuery = 'UPDATE password_reset_attempts SET reset_attempts = ?, last_reset_attempt = NOW() WHERE login = ?';
    const updatePasswordQuery = 'UPDATE newusers SET password = ? WHERE login = ?';
    const updateNewUsersQuery = 'UPDATE newusers SET login_attempts = ?, last_login_attempt = NOW() WHERE login = ?';

    try {
        // Преобразуем email в нижний регистр для нормализации
        const normalizedEmail = email.toLowerCase();

        // Получаем соединение из пула
        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).send('Ошибка сервера');
            }

            connection.query(selectQuery, [normalizedEmail], async (err, users) => {
                if (err) {
                    connection.release();
                    console.error('Ошибка при запросе пользователя:', err);
                    return res.status(500).send('Ошибка сервера');
                }

                if (users.length === 0) {
                    connection.release();
                    return res.status(404).json({ error: 'Пользователь не найден' });
                }

                const user = users[0];
                // Проверка совпадения пароля и подтверждения пароля
                if (password !== confirmPassword) {
                    // Увеличиваем счетчик ошибок сброса пароля
                    return incrementResetAttempts(user.login, connection, res, 'Пароль и подтверждение пароля не совпадают');
                }

                // Проверка валидности пароля
                const passwordValidation = validatePassword(password);
                if (!passwordValidation.success) {
                    // Увеличиваем счетчик ошибок сброса пароля
                    return incrementResetAttempts(user.login, connection, res, passwordValidation.errors);
                }

                // Декодируем токен (предыдущий пароль) для сравнения с паролем из базы данных
                const decodedToken = decodeURIComponent(token);

                // Сравниваем предоставленный токен (предыдущий пароль) с хешированным паролем в базе данных
                if (String(decodedToken) != String(user.password)) {
                    connection.release();
                    return res.status(401).json({ error: 'Неправильный токен' });
                }

                // Проверяем reset_attempts и last_reset_attempt
                connection.query(query, [user.login], async (err, resetResults) => {
                    if (err) {
                        connection.release();
                        console.error('Ошибка при запросе reset_attempts и last_reset_attempt:', err);
                        return res.status(500).send('Ошибка сервера');
                    }

                    const { reset_attempts, last_reset_attempt } = resetResults[0];
                    const currentTime = new Date();
                    const timeDifference = (currentTime - new Date(last_reset_attempt)) / (1000 * 60); // Разница в минутах

                    if (reset_attempts >= 5 && timeDifference < 15) {
                        connection.release();
                        return res.status(403).json({ error: 'Превышено количество попыток сброса пароля. Попробуйте позже.' });
                    }

                    // Хешируем новый пароль
                    const hashedNewPassword = await hashPassword(password);

                    // Обновляем пароль пользователя в базе данных
                    connection.query(updatePasswordQuery, [hashedNewPassword, user.login], async (err) => {
                        if (err) {
                            connection.release();
                            console.error('Ошибка при обновлении пароля:', err);
                            return res.status(500).send('Ошибка сервера');
                        }

                        // Обновляем количество попыток сброса пароля и время последней попытки
                        connection.query(updateQuery, [0, user.login], async (err) => {
                            if (err) {
                                connection.release();
                                console.error('Ошибка при обновлении счетчика сброса пароля:', err);
                                return res.status(500).send('Ошибка сервера');
                            }

                            // Обновляем количество попыток входа и время последней попытки входа
                            connection.query(updateNewUsersQuery, [0, user.login], (err) => {
                                if (err) {
                                    connection.release();
                                    console.error('Ошибка при обновлении счетчика входа:', err);
                                    return res.status(500).send('Ошибка сервера');
                                }

                                // Освобождаем соединение и возвращаем ответ
                                connection.release();
                                res.json({ status: 'ok', message: 'Пароль успешно обновлен' });
                            });
                        });
                    });
                });
            });
        });
    } catch (error) {
        console.error('Ошибка при сбросе пароля:', error);
        res.status(500).send('Ошибка сервера');
    }
}

function incrementResetAttempts(login, connection, res, errorMessage) {
    const query = 'SELECT reset_attempts, last_reset_attempt FROM password_reset_attempts WHERE login = ?';
    const updateQuery = 'UPDATE password_reset_attempts SET reset_attempts = ?, last_reset_attempt = NOW() WHERE login = ?';

    connection.query(query, [login], (err, resetResults) => {
        if (err) {
            connection.release();
            console.error('Ошибка при запросе reset_attempts и last_reset_attempt:', err);
            return res.status(500).send('Ошибка сервера');
        }

        let { reset_attempts, last_reset_attempt } = resetResults[0];
        const currentTime = new Date();
        const timeDifference = (currentTime - new Date(last_reset_attempt)) / (1000 * 60); // Разница в минутах

        // Если прошло более 15 минут с последней попытки сброса пароля, сбрасываем счетчик
        if (timeDifference >= 15) {
            reset_attempts = 0;
        }

        // Увеличиваем счетчик попыток сброса пароля
        reset_attempts += 1;

        // Обновляем счетчик и время последней попытки сброса пароля в базе данных
        connection.query(updateQuery, [reset_attempts, login], (err) => {
            connection.release();
            if (err) {
                console.error('Ошибка при обновлении счетчика сброса пароля:', err);
                return res.status(500).send('Ошибка сервера');
            }

            return res.status(400).json({ error: errorMessage });
        });
    });
}



// Сброс пароля пользователя
function resetPass(req, res) {
    if (req.body.url !== "0" && req.body.url !== "") {
        const query = 'SELECT count(*) <> 0 AS res FROM reset WHERE url = ?';
        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).send('Ошибка сервера');
            }
            connection.query(query, [req.body.url], (err, result) => {
                connection.release(); // Освобождаем соединение после выполнения запроса
                if (err) {
                    console.error('Ошибка при запросе URL для сброса пароля:', err);
                    return res.status(500).send('Ошибка сервера');
                }
                if (result[0].res !== 0) {
                    const updateQuery = 'UPDATE users SET password = ? WHERE mail = ?';
                    const mail = req.body.url.split("=")[0];
                    pool.getConnection((err, connection) => {
                        if (err) {
                            console.error('Ошибка при получении соединения из пула:', err);
                            return res.status(500).send('Ошибка сервера');
                        }
                        connection.query(updateQuery, [md5(req.body.pass), mail], (err) => {
                            connection.release(); // Освобождаем соединение после выполнения запроса
                            if (err) {
                                console.error('Ошибка при обновлении пароля:', err);
                                return res.status(500).send('Ошибка сервера');
                            }
                            const deleteQuery = 'DELETE FROM reset WHERE url LIKE ?';
                            pool.getConnection((err, connection) => {
                                if (err) {
                                    console.error('Ошибка при получении соединения из пула:', err);
                                    return res.status(500).send('Ошибка сервера');
                                }
                                connection.query(deleteQuery, [`${req.body.url}%`], (err) => {
                                    connection.release(); // Освобождаем соединение после выполнения запроса
                                    if (err) {
                                        console.error('Ошибка при удалении URL для сброса пароля:', err);
                                        return res.status(500).send('Ошибка сервера');
                                    }
                                    res.json({ status: "ok" });
                                });
                            });
                        });
                    });
                } else {
                    res.status(404).send('URL для сброса пароля не найден');
                }
            });
        });
    } else {
        res.status(400).send('Недопустимый URL для сброса пароля');
    }
}

async function changePassword(req, res) {
    const { refreshToken, oldPassword, newPassword, confirmPassword } = req.body;
    console.log('В методе changePassword');
    console.log(req.body);

    if (!refreshToken || !oldPassword || !newPassword || !confirmPassword) {
        console.log('Отсутствуют обязательные поля');
        return res.status(400).json({ error: 'Отсутствуют обязательные поля' });
    }

    // Проверяем, совпадают ли новый пароль и подтверждение пароля
    if (newPassword !== confirmPassword) {
        console.log('Новый пароль и подтверждение пароля не совпадают');
        return res.status(400).json({ error: 'Новый пароль и подтверждение пароля не совпадают' });
    }

    // Проверяем валидность нового пароля
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.success) {
        console.log('Новый пароль не соответствует требованиям безопасности');
        return res.status(400).json({ error: passwordValidation.errors });
    }

    try {
        // Находим логин пользователя по refreshToken в таблице UserToken
        const selectTokenQuery = 'SELECT user FROM UserToken WHERE refreshToken = ?';
        const [tokens] = await pool.promise().query(selectTokenQuery, [refreshToken]);
        console.log(tokens);

        if (tokens.length === 0 || !tokens[0].user) { 
            console.log('Недействительный refreshToken');
            return res.status(401).json({ error: 'Недействительный refreshToken' });
        }

        const user = tokens[0].user; // Получаем объект пользователя из tokens
        const login = user; // Присваиваем его значение переменной login

        // Получаем хешированный пароль пользователя из таблицы newusers по логину
        const selectUserQuery = 'SELECT password, email FROM newusers WHERE login = ?';
        const [users] = await pool.promise().query(selectUserQuery, [login]);
        console.log(login);
        console.log(users);

        if (users.length === 0) {
            console.log('Пользователь не найден');
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        const userEmail = users[0].email; // Получаем email пользователя
        console.log(users[0].password);

        // Сравниваем старый пароль с хешированным паролем в базе данных
        const isMatch = await bcrypt.compare(oldPassword, users[0].password);
        if (!isMatch) {
            console.log('Неправильный старый пароль');
            return res.status(401).json({ error: 'Неправильный старый пароль' });
        }

        // Хешируем новый пароль
        const hashedNewPassword = await hashPassword(newPassword);
        console.log(hashedNewPassword);

        // Обновляем пароль пользователя в базе данных
        const updateQuery = 'UPDATE newusers SET password = ? WHERE login = ?';
        await pool.promise().query(updateQuery, [hashedNewPassword, login]);

        // Отправляем email пользователю
        const theme = 'Изменение пароля';
        const text = 'Ваш пароль был успешно изменен. Если это сделали не вы, обратитесь к администратору сайта.';
        const textHtml = '<p>Ваш пароль был успешно изменен. Если это сделали не вы, обратитесь к администратору сайта.</p>';
        
        try {
            await sendMail(userEmail, theme, text, textHtml);
            res.json({ status: 'ok', message: 'Пароль успешно обновлен' });
        } catch (emailError) {
            console.error('Ошибка при отправке электронной почты:', emailError);
            res.status(500).json({ status: 'ok', message: 'Пароль успешно обновлен, но произошла ошибка при отправке уведомления по электронной почте' });
        }
    } catch (error) {
        console.log('Ошибка при смене пароля:', error);
        console.error('Ошибка при смене пароля:', error);
        res.status(500).send('Ошибка сервера');
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

function getOrderHistory(req, res) {
    const { refreshToken } = req.query;

    if (!refreshToken) {
        return res.status(400).json({ error: 'Отсутствует refresh токен' });
    }

    const selectUserQuery = 'SELECT user FROM UserToken WHERE refreshToken = ?';
    const selectOrdersQuery = 'SELECT * FROM OrderHistory WHERE login = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(selectUserQuery, [refreshToken], (err, userResult) => {
            if (err) {
                connection.release();
                console.error('Ошибка при запросе пользователя по refreshToken:', err);
                return res.status(500).send('Ошибка сервера');
            }

            if (userResult && userResult.length > 0) {
                const { user } = userResult[0];

                connection.query(selectOrdersQuery, [user], (err, ordersResult) => {
                    connection.release();
                    
                    if (err) {
                        console.error('Ошибка при запросе истории заказов:', err);
                        return res.status(500).send('Ошибка сервера');
                    }

                    res.status(200).json({ orders: ordersResult });
                });
            } else {
                connection.release();
                res.status(404).send('Пользователь не найден');
            }
        });
    });
}

module.exports = {
    getInfoUser,
    updateInfoUser,
    sendMailReset,
    resetPass,
    checkLoginExistence,
    comparePhoneNumberAndLogin,
    resetPassword,
    changePassword,
    getNewUsers,
    getUserAccessRights,
    updateUserAccessLevel,
    sendNumberReset,
    getOrderHistory,
    getOrderHistoryAdmin
};
