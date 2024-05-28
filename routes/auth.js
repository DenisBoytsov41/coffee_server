/* global ACCESS_TOKEN_EXPIRATION */
/* global REFRESH_TOKEN_EXPIRATION */
/* global ACCESS_TOKEN_SECRET */
/* global REFRESH_TOKEN_SECRET */
const md5 = require('md5');
const jwt = require('jsonwebtoken');
const pool = require('../pool');
const { validateRegistration, hashPassword, comparePasswords } = require('../validation');
const crypto = require('crypto');
//const connsql = require('../database');
const moment = require('moment');

// Admin login method
function loginAdmin(req, res) {
  const query = 'SELECT count(*) <> 0 AS res FROM users WHERE id = 0 AND mail = ? AND password = ?';
  pool.getConnection((err, connection) => {
      if (err) {
          console.error('Ошибка при получении соединения из пула:', err);
          return res.status(500).send('Ошибка сервера');
      }
      connection.query(query, [req.body.mail.toLowerCase(), md5(req.body.pass)], (err, result) => {
          connection.release(); // Освобождаем соединение после выполнения запроса
          if (err) {
              console.error('Ошибка при выполнении запроса loginAdmin:', err);
              return res.status(500).send('Ошибка сервера');
          }
          res.json(result[0]);
      });
  });
}

const registerUser = async (req, res) => {
  const validationResult = validateRegistration(req.body);
  console.log(req.body);
  if (!validationResult.success) {
      return res.status(402).json({ error: validationResult.errors });
  }

  const { firstName, lastName, email, username, password, confirmPassword, gender, phone } = req.body;

  try {
      // Получаем соединение из пула
      pool.getConnection((getConnectionErr, connection) => {
          if (getConnectionErr) {
              console.error('Ошибка при получении соединения из пула: ', getConnectionErr);
              return res.status(500).json({ error: 'Ошибка сервера' });
          }

          // Проверяем, занята ли указанная почта
          const checkEmailQuery = 'SELECT * FROM newusers WHERE email = ?';
          connection.query(checkEmailQuery, [email], async (checkEmailErr, checkEmailResult) => {
              if (checkEmailErr) {
                  console.error('Ошибка при проверке почты: ', checkEmailErr);
                  connection.release(); // Освобождаем соединение после использования
                  return res.status(500).json({ error: 'Ошибка сервера' });
              }

              if (checkEmailResult.length > 0) {
                  connection.release(); // Освобождаем соединение после использования
                  return res.status(400).json({ error: 'Эта почта уже используется' });
              }

              // Проверяем, занят ли указанный логин
              const checkUsernameQuery = 'SELECT * FROM newusers WHERE login = ?';
              connection.query(checkUsernameQuery, [username], async (checkUsernameErr, checkUsernameResult) => {
                  if (checkUsernameErr) {
                      console.error('Ошибка при проверке логина: ', checkUsernameErr);
                      connection.release(); // Освобождаем соединение после использования
                      return res.status(500).json({ error: 'Ошибка сервера' });
                  }

                  if (checkUsernameResult.length > 0) {
                      connection.release(); // Освобождаем соединение после использования
                      return res.status(400).json({ error: 'Этот логин уже используется' });
                  }

                  // Хэшируем пароль
                  const hashedPassword = await hashPassword(password);

                  // Вставляем данные пользователя в базу данных
                  const insertQuery = 'INSERT INTO newusers (firstName, lastName, email, login, password, gender, phone) VALUES (?, ?, ?, ?, ?, ?, ?)';
                  connection.query(insertQuery, [firstName, lastName, email, username, hashedPassword, gender, phone], (insertErr, result) => {
                      connection.release(); // Освобождаем соединение после использования
                      if (insertErr) {
                          console.error('Ошибка при добавлении пользователя: ', insertErr);
                          return res.status(500).json({ error: 'Ошибка сервера' });
                      }
                      res.status(200).json({ message: 'Пользователь успешно зарегистрирован', username: username, jwtToken: null });
                  });
              });
          });
      });
  } catch (error) {
      console.error('Ошибка при выполнении запроса: ', error);
      return res.status(500).json({ error: 'Ошибка сервера' });
  }
};

// Генерация случайной строки в формате hex
const generateRandomSecret = () => {
    return crypto.randomBytes(32).toString('hex');
  };
  
  const generateAccessToken = (user) => {
    console.log("Я тут1");
    return jwt.sign({ 
      username: user.username, 
      guestMode: user.guestMode, 
      currentTheme: user.currentTheme, 
      error: user.error 
    }, global.ACCESS_TOKEN_SECRET, { expiresIn: global.ACCESS_TOKEN_EXPIRATION });
  };
  
  const generateRefreshToken = (user) => {
    console.log("Я тут2");
    console.log(global.REFRESH_TOKEN_SECRET);
    return jwt.sign({ 
      username: user.username, 
      guestMode: user.guestMode,
      currentTheme: user.currentTheme, 
      error: user.error 
    }, global.REFRESH_TOKEN_SECRET, { expiresIn: global.REFRESH_TOKEN_EXPIRATION });
  };
  
  const updateTokensWithTheme = (req, res) => {
    const { loginUsername, newAccessTokenDate, newRefreshTokenDate } = req.body;
  
    const newaccessToken = generateAccessToken(newAccessTokenDate);
    console.log("Новый access: " + newaccessToken);
    const newrefreshToken = generateRefreshToken(newRefreshTokenDate);
    console.log("Новый refresh: " + newrefreshToken);
  
    // Получаем соединение из пула
    pool.getConnection((getConnectionErr, connection) => {
        if (getConnectionErr) {
            console.error('Ошибка при получении соединения из пула: ', getConnectionErr);
            console.log('Ошибка при получении соединения из пула: ', getConnectionErr);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        
        // Обновляем токены в базе данных
        const updateTokenQuery = 'UPDATE UserToken SET refreshToken = ?, createdAt = NOW(), expiresIn = NOW() + INTERVAL ? SECOND WHERE user = ?';
        connection.query(updateTokenQuery, [newrefreshToken, global.REFRESH_TOKEN_EXPIRATION, loginUsername], (updateErr, updateResult) => {
            connection.release(); // Освобождаем соединение после использования
            if (updateErr) {
                console.error('Ошибка при обновлении refresh token в базе данных: ', updateErr);
                console.log('Ошибка при обновлении refresh token в базе данных: ', updateErr);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            return res.status(200).json({ 
                message: 'Токены успешно обновлены', 
                accessToken: newaccessToken, 
                refreshToken: newrefreshToken, 
                username: loginUsername, 
                jwtToken: newaccessToken 
            });
        });
    });
};

const loginUser = async (req, res) => {
    const { loginOrEmail, pass } = req.body;
    console.log(loginOrEmail);
    console.log(pass);
    console.log(req.body);

    // Генерация ACCESS_TOKEN_SECRET и REFRESH_TOKEN_SECRET
    global.ACCESS_TOKEN_SECRET = generateRandomSecret();
    global.REFRESH_TOKEN_SECRET = generateRandomSecret();

    // Установка секретных ключей в переменные среды
    global.REFRESH_TOKEN_EXPIRATION = 3600;
    global.ACCESS_TOKEN_EXPIRATION = 180;

    // Проверка является ли ввод email или логином
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(loginOrEmail);
    const checkQuery = isEmail 
        ? 'SELECT * FROM newusers WHERE email = ?' 
        : 'SELECT * FROM newusers WHERE login = ?';

    pool.getConnection((getConnectionErr, connection) => {
        if (getConnectionErr) {
            console.error('Ошибка при получении соединения из пула: ', getConnectionErr);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        connection.query(checkQuery, [loginOrEmail], async (checkErr, checkResult) => {
            if (checkErr) {
                connection.release();
                console.error('Ошибка при проверке пользователя: ', checkErr);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (checkResult.length === 0) {
                connection.release();
                return res.status(401).json({ error: 'Пользователь с таким логином или email не найден' });
            }
            
            const user = checkResult[0];
            console.log(user);
            console.log(checkResult);

            // Проверяем, прошло ли уже 30 минут с последней неудачной попытки входа
            const lastLoginAttempt = new Date(user.last_login_attempt).getTime();
            const thirtyMinutesAgo = Date.now() - 30 * 60 * 1000;
            if (user.login_attempts >= 5 && lastLoginAttempt > thirtyMinutesAgo) {
                connection.release();
                // Если количество неудачных попыток входа больше или равно 5 и последняя неудачная попытка была менее 30 минут назад
                return res.status(401).json({ error: 'Слишком много неудачных попыток входа. Повторите попытку через 30 минут.' });
            }
            else if (lastLoginAttempt <= thirtyMinutesAgo) {
                // Если прошло уже более 30 минут с последней неудачной попытки входа, обнуляем счетчик неудачных попыток
                const resetAttemptsQuery = 'UPDATE newusers SET login_attempts = 0 WHERE login = ?';
                connection.query(resetAttemptsQuery, [user.login], (resetErr) => {
                    if (resetErr) {
                        connection.release();
                        console.error('Ошибка при сбросе счетчика попыток входа:', resetErr);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }
                });
            }

            const isPasswordValid = await comparePasswords(pass, user.password);
            if (!isPasswordValid) {
                const updateQuery = 'UPDATE newusers SET login_attempts = login_attempts + 1, last_login_attempt = NOW() WHERE login = ?';
                connection.query(updateQuery, [user.login], (updateErr) => {
                    connection.release();
                    if (updateErr) {
                        console.error('Error during updating login attempts:', updateErr);
                        return res.status(500).json({ error: 'Server error' });
                    }
                    return res.status(401).json({ error: 'Неверный пароль' });
                });
                return; // Ensure no further execution in case of invalid password
            }

            // Обнуляем счетчик неудачных попыток входа после успешного входа
            const resetAttemptsQueryAfterSuccess = 'UPDATE newusers SET login_attempts = 0 WHERE login = ?';
            connection.query(resetAttemptsQueryAfterSuccess, [user.login], (resetErr) => {
                if (resetErr) {
                    connection.release();
                    console.error('Ошибка при сбросе счетчика попыток входа после успешного входа:', resetErr);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                const refreshTokenQuery = 'SELECT refreshToken FROM UserToken WHERE user = ? AND expiresIn > NOW()';
                const userIdentifier = user.login;
                console.log("Пользователь " + userIdentifier);

                connection.query(refreshTokenQuery, [userIdentifier], (tokenErr, tokenResult) => {
                    connection.release();
                    if (tokenErr) {
                        console.error('Ошибка при проверке refresh token: ', tokenErr);
                        console.log('Ошибка при проверке refresh token: ', tokenErr);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    if (tokenResult.length > 0) {
                        const refreshToken = tokenResult[0].refreshToken;
                        const accessToken = generateAccessToken({ 
                            username: user.login, 
                            guestMode: false, 
                            error: null 
                        });
                        return res.status(200).json({ 
                            message: 'Вход в систему', 
                            accessToken: accessToken, 
                            refreshToken: refreshToken, 
                            username: user.login 
                        });
                    } else {
                        const accessToken = generateAccessToken({ 
                            username: user.login, 
                            guestMode: false, 
                            error: null 
                        });
                        const refreshToken = generateRefreshToken({ 
                            username: user.login, 
                            guestMode: false, 
                            error: null 
                        });

                        pool.getConnection((insertConnectionErr, insertConnection) => {
                            if (insertConnectionErr) {
                                console.error('Ошибка при получении соединения для сохранения refresh token: ', insertConnectionErr);
                                console.log('Ошибка при получении соединения для сохранения refresh token: ', insertConnectionErr);
                                return res.status(500).json({ error: 'Ошибка сервера' });
                            }

                            const insertTokenQuery = 'INSERT INTO UserToken (user, refreshToken, expiresIn) VALUES (?, ?, NOW() + INTERVAL ? SECOND)';
                            insertConnection.query(insertTokenQuery, [userIdentifier, refreshToken, global.REFRESH_TOKEN_EXPIRATION], (insertErr) => {
                                insertConnection.release();
                                if (insertErr) {
                                    console.error('Ошибка при сохранении refresh token в базе данных: ', insertErr);
                                    console.log('Ошибка при сохранении refresh token в базе данных: ', insertErr);
                                    return res.status(500).json({ error: 'Ошибка сервера' });
                                }
                                res.status(200).json({ 
                                    message: 'Вход в систему', 
                                    accessToken: accessToken, 
                                    refreshToken: refreshToken, 
                                    username: user.login 
                                });
                            });
                        });
                    }
                });
            });
        });
    });
};
  
// Обновление Access Token
const refreshToken = (req, res) => {
  const refreshTokenFromStorage = req.params.token;

  if (!refreshTokenFromStorage) {
    console.log('Отсутствует refreshToken в запросе');
    return res.status(401).json({ error: 'Отсутствует refreshToken в запросе' });
  }

  pool.getConnection((getConnectionErr, connection) => {
      if (getConnectionErr) {
          console.error('Ошибка при получении соединения из пула: ', getConnectionErr);
          console.log('Ошибка при получении соединения из пула: ', getConnectionErr);
          return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
      }

      connection.query('SELECT * FROM UserToken WHERE refreshToken = ?', [refreshTokenFromStorage], (err, result) => {
          connection.release();
          if (err) {
              console.error('Ошибка при проверке refreshToken в базе данных: ', err);
              console.log('Ошибка при проверке refreshToken в базе данных: ', err);
              return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
          }

          if (result.length === 0) {
              console.log('Недействительный refreshToken');
              return res.status(403).json({ error: 'Недействительный refreshToken' });
          }

          jwt.verify(refreshTokenFromStorage, global.REFRESH_TOKEN_SECRET, (jwtErr, decoded) => {
              if (jwtErr) {
                  console.error('Ошибка при проверке валидности refreshToken:', jwtErr);
                  console.log('Ошибка при проверке валидности refreshToken:', jwtErr);
                  pool.getConnection((deleteConnectionErr, deleteConnection) => {
                      if (deleteConnectionErr) {
                          console.log('Ошибка при получении соединения для удаления refreshToken из базы данных:', deleteConnectionErr);
                          console.error('Ошибка при получении соединения для удаления refreshToken из базы данных:', deleteConnectionErr);
                      }
                      deleteConnection.query('DELETE FROM UserToken WHERE refreshToken = ?', [refreshTokenFromStorage], (deleteErr, deleteResult) => {
                          deleteConnection.release();
                          if (deleteErr) {
                              console.log('Ошибка при удалении refreshToken из базы данных:', deleteErr);
                              console.error('Ошибка при удалении refreshToken из базы данных:', deleteErr);
                          }
                          //localStorage.removeItem('refreshToken');
                          console.log('Недействительный refreshToken');
                          return res.status(403).json({ error: 'Недействительный refreshToken' });
                      });
                  });
              } else {
                  const accessToken = jwt.sign({ 
                      username: decoded.username, 
                      guestMode: decoded.guestMode, 
                      currentTheme: decoded.currentTheme, 
                      error: decoded.error 
                  }, global.ACCESS_TOKEN_SECRET, { expiresIn: global.ACCESS_TOKEN_EXPIRATION });

                  return res.status(200).json({ accessToken: accessToken });
              }
          });
      });
  });
};
 
const checkRefreshToken = (req, res) => {
    console.log("Я хоть тут1");
    const { refreshToken, refreshTokenExpiration } = req.body;
    console.log(refreshToken);
    console.log("--");
    console.log(refreshTokenExpiration);
    if (!refreshToken) {
        console.log('Отсутствует refreshToken в запросе');
        return res.status(400).json({ error: 'Отсутствует refreshToken в запросе' });
    }

    pool.getConnection((getConnectionErr, connection) => {
        if (getConnectionErr) {
            console.error('Ошибка при получении соединения из пула: ', getConnectionErr);
            console.log('Ошибка при получении соединения из пула: ', getConnectionErr);
            return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
        }

        connection.query('SELECT * FROM UserToken WHERE refreshToken = ?', [refreshToken], (err, result) => {
            connection.release();
            console.log("Я хоть тут2");
            if (err) {
                console.error('Ошибка при проверке refreshToken в базе данных:', err);
                console.log('Ошибка при проверке refreshToken в базе данных:', err);
                console.log("Я хоть тут3");
                return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
            }
            if (result.length === 0) {
                console.log("Я хоть тут4");
                console.log('refreshToken не найден');
                return res.status(404).json({ error: 'refreshToken не найден' });
            }
            console.log("Я хоть тут5");
            const dbRefreshToken = result[0];
            const dbExpiration = dbRefreshToken.expiresIn;
            const expirationMoment = moment(dbExpiration);
            const refreshTokenExpirationMoment = moment(refreshTokenExpiration);

            const timeDifference = Math.abs(expirationMoment.diff(refreshTokenExpirationMoment, 'seconds'));

            console.log(refreshTokenExpiration);
            console.log(expirationMoment.format('YYYY-MM-DD HH:mm:ss'));
            console.log(`Time difference: ${timeDifference} seconds`);

            if (refreshTokenExpiration && timeDifference <= 5) {
                console.log("Я хоть тут6");
                return res.status(200).json({ message: "Всё ок" });
            } else {
                console.log("Я хоть тут7");
                pool.getConnection((deleteConnectionErr, deleteConnection) => {
                    if (deleteConnectionErr) {
                        console.error('Ошибка при получении соединения для удаления refreshToken из базы данных:', deleteConnectionErr);
                        console.log('Ошибка при получении соединения для удаления refreshToken из базы данных:', deleteConnectionErr);
                    }
                    deleteConnection.query('DELETE FROM UserToken WHERE refreshToken = ?', [refreshToken], (deleteErr, deleteResult) => {
                        deleteConnection.release();
                        if (deleteErr) {
                            console.log("Я хоть тут8");
                            console.log('Ошибка при удалении refreshToken из базы данных:', deleteErr);
                            console.error('Ошибка при удалении refreshToken из базы данных:', deleteErr);
                        }
                    });
                });
                console.log("Я хоть тут9");
                console.log('refreshToken не найден в локальном хранилище или истек его срок действия');
                return res.status(401).json({ error: 'refreshToken не найден в локальном хранилище или истек его срок действия' });
            }
        });
    });
};
  
  
  
const logoutUser = (req, res) => {
  const { refreshToken } = req.body;
  console.log("refreshToken: " + refreshToken);
  if (!refreshToken) {
      console.log('Отсутствует refreshToken в запросе');
      return res.status(400).json({ error: 'Отсутствует refreshToken в запросе' });
  }

  jwt.verify(refreshToken, global.REFRESH_TOKEN_SECRET, (err, decoded) => {
      if (err) {
          console.error('Ошибка при проверке валидности refreshToken:', err);
          console.log('Ошибка при проверке валидности refreshToken:', err);
          return res.status(401).json({ error: 'Недействительный токен' });
      }
      // Получаем соединение из пула
      pool.getConnection((getConnectionErr, connection) => {
          if (getConnectionErr) {
              console.error('Ошибка при получении соединения из пула: ', getConnectionErr);
              console.log('Ошибка при получении соединения из пула: ', getConnectionErr);
              return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
          }
          // Проверяем refreshToken в базе данных и удаляем его, если он существует
          connection.query('DELETE FROM UserToken WHERE refreshToken = ?', [refreshToken], (queryErr, result) => {
              connection.release(); // Освобождаем соединение обратно в пул
              if (queryErr) {
                  console.error('Ошибка при удалении refreshToken из базы данных:', queryErr);
                  console.log('Ошибка при удалении refreshToken из базы данных:', queryErr);
                  return res.status(500).json({ error: 'Ошибка сервера' });
              } else {
                  console.log('refreshToken успешно удалён из базы данных');
                  return res.status(200).json({ message: 'Вы успешно вышли из системы' });
              }
          });
      });
  });
};

const deleteRefreshToken = (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
      return res.status(400).json({ error: 'Отсутствует refreshToken в запросе' });
  }
  // Получаем соединение из пула
  pool.getConnection((getConnectionErr, connection) => {
      if (getConnectionErr) {
          console.error('Ошибка при получении соединения из пула: ', getConnectionErr);
          console.log('Ошибка при получении соединения из пула: ', getConnectionErr);
          return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
      }
      connection.query('DELETE FROM UserToken WHERE refreshToken = ?', [refreshToken], (deleteErr, deleteResult) => {
          connection.release(); // Освобождаем соединение обратно в пул
          if (deleteErr) {
              console.error('Ошибка при удалении refreshToken из базы данных:', deleteErr);
              console.log('Ошибка при удалении refreshToken из базы данных:', deleteErr);
              return res.status(500).json({ error: 'Ошибка при удалении refreshToken из базы данных' });
          }
          console.log('Токен успешно удален из базы данных');
          return res.status(200).json({ message: 'Токен успешно удален из базы данных' });
      });
  });
};

const getUserByRefreshToken = (refreshToken, callback) => {
  // Поиск refreshToken в таблице UserToken
  const refreshTokenQuery = 'SELECT user FROM UserToken WHERE refreshToken = ?';
  // Получаем соединение из пула
  pool.getConnection((getConnectionErr, connection) => {
      if (getConnectionErr) {
          console.error('Ошибка при получении соединения из пула:', getConnectionErr);
          console.log('Ошибка при получении соединения из пула:', getConnectionErr);
          callback(getConnectionErr, null);
      } else {
          connection.query(refreshTokenQuery, [refreshToken], (err, result) => {
              // Освобождаем соединение обратно в пул
              connection.release();
              if (err) {
                  console.error('Ошибка при поиске refreshToken в базе данных:', err);
                  console.log('Ошибка при поиске refreshToken в базе данных:', err);
                  callback(err, null);
              } else {
                  if (result.length === 0) {
                      // Если refreshToken не найден, возвращаем ошибку
                      const error = 'refreshToken не найден в базе данных';
                      callback(error, null);
                  } else {
                      // Если refreshToken найден, получаем логин пользователя
                      const username = result[0].user;
                      // Запрос к таблице newusers для получения данных пользователя
                      const getUserQuery = 'SELECT * FROM newusers WHERE login = ?';
                      connection.query(getUserQuery, [username], (userErr, userResult) => {
                          // Освобождаем соединение обратно в пул
                          connection.release();
                          if (userErr) {
                              console.error('Ошибка при получении данных пользователя из базы данных:', userErr);
                              console.log('Ошибка при получении данных пользователя из базы данных:', userErr);
                              callback(userErr, null);
                          } else {
                              // Возвращаем данные пользователя
                              const user = userResult[0];
                              callback(null, user);
                          }
                      });
                  }
              }
          });
      }
  });
};


  const getUserByRefreshTokenHandler = (req, res) => {
    const refreshToken = req.query.refreshToken;
    getUserByRefreshToken(refreshToken, (err, user) => {
      if (err) {
        console.error('Ошибка при получении данных пользователя:', err);
        res.status(500).json({ error: 'Ошибка при получении данных пользователя' });
      } else {
        res.status(200).json(user);
      }
    });
  };
module.exports = {
    loginAdmin,
    registerUser,
    loginUser,
    logoutUser,
    deleteRefreshToken, 
    refreshToken,
    checkRefreshToken, 
    updateTokensWithTheme,
    getUserByRefreshTokenHandler
};
