const twilio = require('twilio');
const pool = require('../pool');
require('dotenv').config();


// Конфигурация Twilio
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;
const client = twilio(accountSid, authToken);

// Метод отправки SMS с кодом восстановления пароля
async function sendPasswordResetSMS(req, res) {
    const { phone, login } = req.body;
    const code = generateRandomCode(); // Генерация случайного кода для восстановления пароля

    try {
        const phoneString = String(phone);
        const codeString = String(code);
        console.log(req.body);
        console.log(phone);
        console.log(login);
        /*await client.messages.create({
            body: `Ваш код для восстановления пароля: ${codeString}`,
            from: twilioPhoneNumber, // Используйте ваш Twilio номер
            to: phoneString
        });*/
        await saveResetCode(login, code); // Сохранение кода и логина для дальнейшей проверки
        res.status(200).send({ code }); // Отправляем код как часть ответа
    } catch (error) {
        console.error('Ошибка при отправке SMS:', error);
        res.status(500).send('Ошибка при отправке SMS');
    }
}


// Генерация случайного кода для восстановления пароля
function generateRandomCode() {
    return Math.floor(1000 + Math.random() * 9000); // Генерация четырехзначного случайного числа
}

async function saveResetCode(login, code) {
    const query = `
        INSERT INTO password_reset_attempts (login, reset_code, reset_attempts, last_reset_attempt)
        VALUES (?, ?, 0, NOW())
        ON DUPLICATE KEY UPDATE reset_code = VALUES(reset_code), reset_attempts = 0, last_reset_attempt = VALUES(last_reset_attempt)
    `;
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            throw new Error('Ошибка сервера');
        }

        connection.query(query, [login, code], (err) => {
            connection.release(); // Освобождаем соединение после выполнения запроса

            if (err) {
                console.error('Ошибка при сохранении кода для сброса пароля:', err);
                throw new Error('Ошибка сервера');
            }
        });
    });
}
async function checkResetCode(req, res) {
    const { login, resetCode } = req.body;
    console.log(req.body);
    const query = 'SELECT reset_code, reset_attempts, last_reset_attempt FROM password_reset_attempts WHERE login = ?';
    const updateQuery = 'UPDATE password_reset_attempts SET reset_attempts = ?, last_reset_attempt = NOW() WHERE login = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            console.log('Ошибка при получении соединения из пула', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        connection.query(query, [login], (err, result) => {
            if (err) {
                connection.release(); // Освобождаем соединение после выполнения запроса
                console.error('Ошибка при проверке кода сброса:', err);
                console.log('Ошибка при проверке кода сброса:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (result && result.length > 0) {
                const { reset_code, reset_attempts, last_reset_attempt } = result[0];
                const lastAttemptDate = new Date(last_reset_attempt);
                const currentTime = new Date();
                const timeDifference = (currentTime - lastAttemptDate) / (1000 * 60); // Разница в минутах

                if (reset_attempts >= 5 && timeDifference < 10) {
                    connection.release(); // Освобождаем соединение после выполнения запроса
                    console.log('Превышено количество попыток. Попробуйте позже.');
                    return res.status(403).json({ error: 'Превышено количество попыток. Попробуйте позже.' });
                }

                if (reset_code === resetCode) {
                    const newResetAttempts = 0; // Сбрасываем счетчик при успешной проверке
                    connection.query(updateQuery, [newResetAttempts, login], (err) => {
                        connection.release(); // Освобождаем соединение после выполнения запроса

                        if (err) {
                            console.error('Ошибка при обновлении попыток сброса пароля:', err);
                            console.log('Ошибка при обновлении попыток сброса пароля:', err);
                            return res.status(500).json({ error: 'Ошибка сервера' });
                        }

                        res.json({ match: true });
                    });
                } else {
                    const newResetAttempts = timeDifference >= 10 ? 1 : reset_attempts + 1;

                    connection.query(updateQuery, [newResetAttempts, login], (err) => {
                        connection.release(); // Освобождаем соединение после выполнения запроса

                        if (err) {
                            console.error('Ошибка при обновлении попыток сброса пароля:', err);
                            console.log('Ошибка при обновлении попыток сброса пароля:', err);
                            return res.status(500).json({ error: 'Ошибка сервера' });
                        }

                        res.json({ match: false });
                    });
                }
            } else {
                connection.release(); // Освобождаем соединение после выполнения запроса
                console.log('Пользователь не найден');
                res.status(404).json({ error: 'Пользователь не найден' });
            }
        });
    });
}


module.exports = {sendPasswordResetSMS, checkResetCode};