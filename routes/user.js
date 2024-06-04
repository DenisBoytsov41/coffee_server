const md5 = require('md5');
//const connsql = require('../database');
const pool = require('../pool');
const { sendMail } = require('../mailer');
const { validateSmen } = require('../validationsmen');
const crypto = require('crypto');
const {validatePassword} = require('../validatePassword');
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
                const text = 'Ваши данные профиля были успешно обновлены.';
                const textHtml = '<p>Ваши данные профиля были успешно обновлены.</p>';
  
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

  const selectQuery = 'SELECT COUNT(*) AS count, login_attempts, last_login_attempt FROM newusers WHERE login = ?';
  const updateQuery = 'UPDATE newusers SET login_attempts = ?, last_login_attempt = NOW() WHERE login = ?';

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
              const loginAttempts = result[0].login_attempts;
              const lastLoginAttempt = new Date(result[0].last_login_attempt);
              const currentTime = new Date();
              const timeDifference = (currentTime - lastLoginAttempt) / (1000 * 60); // Разница в минутах

              if (loginAttempts >= 5 && timeDifference < 30) {
                  connection.release(); // Освобождаем соединение после выполнения запроса
                  return res.status(403).json({ error: 'Превышено количество попыток входа. Попробуйте позже.' });
              }

              const newLoginAttempts = timeDifference >= 15 ? 1 : loginAttempts + 1;

              connection.query(updateQuery, [newLoginAttempts, login], (err) => {
                  connection.release(); // Освобождаем соединение после выполнения запроса
                  if (err) {
                      console.error('Ошибка при обновлении попыток входа:', err);
                      return res.status(500).json({ error: 'Ошибка сервера' });
                  }

                  if (newLoginAttempts > 5) {
                      return res.status(403).json({ error: 'Превышено количество попыток входа. Попробуйте позже.' });
                  }

                  res.json({ exists: true });
              });
          } else {
              connection.query(updateQuery, [0, login], (err) => {
                  connection.release(); // Освобождаем соединение после выполнения запроса
                  if (err) {
                      console.error('Ошибка при обновлении попыток входа:', err);
                      return res.status(500).json({ error: 'Ошибка сервера' });
                  }
                  res.status(404).json({ exists: false, message: 'Логин не найден' });
              });
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
  const insertQuery = 'INSERT INTO password_reset_attempts (login, reset_attempts, last_reset_attempt) VALUES (?, ?, NOW())';
  const updateQuery = 'UPDATE password_reset_attempts SET reset_attempts = ?, last_reset_attempt = NOW() WHERE login = ?';
  const resetInsertQuery = "INSERT INTO reset (url) VALUES (?)";

  pool.getConnection((err, connection) => {
      if (err) {
          console.error('Ошибка при получении соединения из пула:', err);
          return res.status(500).send('Ошибка сервера');
      }

      connection.query(selectQuery, [email], (err, result) => {
          if (err) {
              connection.release(); // Освобождаем соединение после выполнения запроса
              console.error('Ошибка при запросе пользователя:', err);
              return res.status(500).send('Ошибка сервера');
          }

          if (result && result.length > 0) {
              const login = result[0].login;
              const password = result[0].password;

              connection.query(insertQuery, [login, 1], (err, result) => {
                  if (err && err.code !== 'ER_DUP_ENTRY') { // Если ошибка не связана с дублированием записи
                      connection.release(); // Освобождаем соединение после выполнения запроса
                      console.error('Ошибка при создании записи в таблице password_reset_attempts:', err);
                      return res.status(500).send('Ошибка сервера');
                  }

                  connection.query(updateQuery, [1, login], (err, result) => {
                      if (err) {
                          connection.release(); // Освобождаем соединение после выполнения запроса
                          console.error('Ошибка при обновлении попыток сброса пароля:', err);
                          return res.status(500).send('Ошибка сервера');
                      }

                      const encodedPassword = encodeURIComponent(password); // Кодируем полученный пароль
                      const resetURL = `http://localhost:3000/resetURL/${email}/${encodedPassword}`;
                      const emailSubject = 'Восстановление пароля';
                      const emailBody = 'Это сообщение отправлено для восстановления пароля.';
                      const emailHtml = `<a href=${resetURL}>Перейдите по ссылке для восстановления пароля</a>`;

                      connection.query(resetInsertQuery, [`${resetURL}/${uniqueKey}`], async (err) => {
                          connection.release(); // Освобождаем соединение после выполнения запроса

                          if (err) {
                              console.error('Ошибка при добавлении URL для сброса пароля:', err);
                              return res.status(500).send('Ошибка сервера');
                          }

                          try {
                              await sendMail(email, emailSubject, emailBody, emailHtml);
                              res.json({ status: "ok" });
                          } catch (error) {
                              console.error('Ошибка при отправке письма:', error);
                              res.status(500).send('Ошибка сервера');
                          }
                      });
                  });
              });
          } else {
              connection.release(); // Освобождаем соединение после выполнения запроса
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
    const insertQuery = 'INSERT INTO password_reset_attempts (login, reset_attempts, last_reset_attempt) VALUES (?, ?, NOW())';
    const updateQuery = 'UPDATE password_reset_attempts SET reset_attempts = reset_attempts + 1, last_reset_attempt = NOW() WHERE login = ?';
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

            connection.query(insertQuery, [login, 1], (err) => {
                if (err && err.code !== 'ER_DUP_ENTRY') {
                    connection.release();
                    console.error('Ошибка при создании записи в таблице password_reset_attempts:', err);
                    return res.status(500).send('Ошибка сервера');
                }

                const queryToUse = err && err.code === 'ER_DUP_ENTRY' ? updateQuery : insertQuery;
                const paramsToUse = err && err.code === 'ER_DUP_ENTRY' ? [login] : [login, 1];

                connection.query(queryToUse, paramsToUse, (err) => {
                    if (err) {
                        connection.release();
                        console.error('Ошибка при обновлении попыток сброса пароля:', err);
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

  const selectQuery = 'SELECT phone, login_attempts, last_login_attempt FROM newusers WHERE login = ?';
  const updateQuery = 'UPDATE newusers SET login_attempts = ?, last_login_attempt = NOW() WHERE login = ?';

  pool.getConnection((err, connection) => {
      if (err) {
          console.error('Ошибка при получении соединения из пула:', err);
          return res.status(500).send('Ошибка сервера');
      }

      connection.query(selectQuery, [login], (err, result) => {
          if (err) {
              connection.release(); // Освобождаем соединение после выполнения запроса
              console.error('Ошибка при запросе номера телефона пользователя:', err);
              return res.status(500).send('Ошибка сервера');
          }

          if (result && result.length > 0) {
              const { phone: userPhone, login_attempts, last_login_attempt } = result[0];
              const formattedUserPhone = userPhone.replace(/\s|\(|\)/g, ''); // Обработка номера телефона из базы данных

              const lastAttemptDate = new Date(last_login_attempt);
              const currentTime = new Date();
              const timeDifference = (currentTime - lastAttemptDate) / (1000 * 60); // Разница в минутах

              if (login_attempts >= 5 && timeDifference < 30) {
                  connection.release(); // Освобождаем соединение после выполнения запроса
                  return res.status(403).json({ error: 'Превышено количество попыток. Попробуйте позже.' });
              }

              if (formattedUserPhone === phone) {
                  const newLoginAttempts = 0; // Сбрасываем счетчик при успешной проверке
                  connection.query(updateQuery, [newLoginAttempts, login], (err) => {
                      connection.release(); // Освобождаем соединение после выполнения запроса

                      if (err) {
                          console.error('Ошибка при обновлении попыток входа:', err);
                          return res.status(500).send('Ошибка сервера');
                      }

                      res.json({ match: true });
                  });
              } else {
                  const newLoginAttempts = timeDifference >= 15 ? 1 : login_attempts + 1;

                  connection.query(updateQuery, [newLoginAttempts, login], (err) => {
                      connection.release(); // Освобождаем соединение после выполнения запроса

                      if (err) {
                          console.error('Ошибка при обновлении попыток входа:', err);
                          return res.status(500).send('Ошибка сервера');
                      }

                      res.json({ match: false });
                  });
              }
          } else {
              connection.release(); // Освобождаем соединение после выполнения запроса
              res.status(404).send('Пользователь не найден');
          }
      });
  });
}
async function resetPassword(req, res) {
  const { email, token, password } = req.body;
  console.log(req.body);

  if (!email || !token || !password) {
      return res.status(400).json({ error: 'Отсутствуют обязательные поля' });
  }

  try {
      // Преобразуем email в нижний регистр для нормализации
      const normalizedEmail = email.toLowerCase();

      // Запрос для получения логина и текущего хешированного пароля пользователя
      const selectQuery = 'SELECT login, password FROM newusers WHERE email = ?';
      const [users] = await pool.promise().query(selectQuery, [normalizedEmail]);

      if (users.length === 0) {
          return res.status(404).json({ error: 'Пользователь не найден' });
      }

      const user = users[0];

      // Декодируем токен (предыдущий пароль) для сравнения с паролем из базы данных
      const decodedToken = decodeURIComponent(token);
      console.log(decodedToken)
      console.log(user.password)

      // Сравниваем предоставленный токен (предыдущий пароль) с хешированным паролем в базе данных
      if (String(decodedToken) != String(user.password)) {
          return res.status(401).json({ error: 'Неправильный токен' });
      }

      // Хешируем новый пароль
      const hashedNewPassword = await hashPassword(password); // Дожидаемся завершения хеширования пароля
      console.log(password);
      console.log(String(hashedNewPassword));

      // Обновляем пароль пользователя в базе данных
      const updateQuery = 'UPDATE newusers SET password = ? WHERE login = ?';
      await pool.promise().query(updateQuery, [hashedNewPassword, user.login]);

      res.json({ status: 'ok', message: 'Пароль успешно обновлен' });
  } catch (error) {
      console.error('Ошибка при сбросе пароля:', error);
      res.status(500).send('Ошибка сервера');
  }
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
        const selectUserQuery = 'SELECT password FROM newusers WHERE login = ?';
        const [users] = await pool.promise().query(selectUserQuery, [login]);
        console.log(login);
        console.log(users);

        if (users.length === 0) {
            console.log('Пользователь не найден');
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
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

        res.json({ status: 'ok', message: 'Пароль успешно обновлен' });
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
    sendNumberReset
};
