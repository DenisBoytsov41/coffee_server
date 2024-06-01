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

                const adminQuery = 'SELECT COUNT(*) AS count FROM AdminUsers WHERE login = ? AND password = ?';

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
        });
    });
}