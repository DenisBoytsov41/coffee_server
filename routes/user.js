const md5 = require('md5');
//const connsql = require('../database');
const pool = require('../pool');
const { sendMail } = require('../mailer');
const { validateSmen } = require('../validationsmen');
const crypto = require('crypto');
const {validatePassword} = require('../validatePassword');
const uuid = require('uuid');
const bcrypt = require('bcrypt');

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
                connection.release();
  
                if (err) {
                  console.error('Ошибка при запросе user info:', err);
                  return res.status(500).send('Ошибка сервера');
                }
  
                res.json({ status: 'ok' });
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
    resetPassword
};
