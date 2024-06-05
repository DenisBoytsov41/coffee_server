const md5 = require('md5');
//const connsql = require('../database');
const pool = require('../pool');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const sharp = require('sharp');

// Get all items method
function getTovar(req, res) {
    console.log(req.body);
    const query = 'SELECT * FROM Tovar';

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

            console.log("Данные о товарах получены успешно");
            res.json(result);
        });
    });
}
function checkAdminAccessJson(req, res) {
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
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (tokenResult.length === 0) {
                connection.release();
                return res.status(403).json({ error: 'Недостаточно прав' });
            }

            const userLogin = tokenResult[0].user;

            const accessQuery = 'SELECT access_level FROM user_access_rights WHERE login = ?';

            connection.query(accessQuery, [userLogin], (err, accessResult) => {
                connection.release();
                if (err) {
                    console.error('Ошибка при проверке уровня доступа пользователя:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                if (accessResult.length === 0 || accessResult[0].access_level !== 'admin') {
                    return res.status(403).json({ error: 'Недостаточно прав' });
                }

                // Если все проверки пройдены успешно, отправляем OK-ответ
                res.json({ status: "ok" });
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

                return callback(null, true);
            });
        });
    });
}


function deleteItem(req, res) {
    const { refreshToken, id } = req.body;

    if (!refreshToken || !id) {
        return res.status(400).send('Bad Request');
    }

    checkAdminAccess(refreshToken, (err, isAdmin, errorMsg) => {
        if (err) {
            return res.status(500).send('Ошибка сервера');
        }

        if (!isAdmin) {
            return res.status(403).send(errorMsg);
        }

        const deleteQuery = 'DELETE FROM Tovar WHERE id = ?';

        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).send('Ошибка сервера');
            }

            connection.query(deleteQuery, [id], (err) => {
                connection.release();
                if (err) {
                    console.error('Ошибка при удалении элемента:', err);
                    return res.status(500).send('Ошибка сервера');
                }
                res.json({ status: "ok" });
            });
        });
    });
}

// Add item method
function addItem(req, res) {
    const { refreshToken, name, opisanie, price, optprice, PhotoPath } = req.body;

    if (!refreshToken) {
        return res.status(400).send('Bad Request');
    }

    checkAdminAccess(refreshToken, (err, isAdmin, errorMsg) => {
        if (err) {
            return res.status(500).send('Ошибка сервера');
        }

        if (!isAdmin) {
            return res.status(403).send(errorMsg);
        }

        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).send('Ошибка сервера');
            }

            // Параметризованный запрос для получения следующего доступного ID
            const getNextIdQuery = 'SELECT MAX(id) + 1 AS ID FROM Tovar';
            connection.query(getNextIdQuery, (err, result) => {
                if (err) {
                    console.error('Ошибка при получении следующего доступного ID:', err);
                    connection.release();
                    return res.status(500).send('Ошибка сервера');
                }

                const nextId = result[0].ID || 1; // Если в результате нет ID, используем 1
                // Параметризованный запрос для добавления элемента
                const addItemQuery = 'INSERT INTO Tovar (id, name, opisanie, price, optprice, PhotoPath) VALUES (?, ?, ?, ?, ?, ?)';
                connection.query(addItemQuery, [nextId, name, opisanie, price, optprice, PhotoPath || ''], (err) => {
                    connection.release();
                    if (err) {
                        console.error('Ошибка при добавлении элемента:', err);
                        return res.status(500).send('Ошибка сервера');
                    }
                    res.json({ status: "ok" });
                });
            });
        });
    });
}

// Update item method
function updateItem(req, res) {
    const { refreshToken, id, name, opisanie, price, optprice, PhotoPath } = req.body;

    if (!refreshToken || !id || !name || !opisanie || !price || !optprice) {
        return res.status(400).send('Bad Request');
    }

    checkAdminAccess(refreshToken, (err, isAdmin, errorMsg) => {
        if (err) {
            return res.status(500).send('Ошибка сервера');
        }

        if (!isAdmin) {
            return res.status(403).send(errorMsg);
        }

        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Ошибка при получении соединения из пула:', err);
                return res.status(500).send('Ошибка сервера');
            }

            // Параметризованный запрос для обновления элемента
            const updateQuery = 'UPDATE Tovar SET name = ?, opisanie = ?, price = ?, optprice = ?, PhotoPath = ? WHERE id = ?';
            connection.query(updateQuery, [name, opisanie, price, optprice, PhotoPath || '', id], (err) => {
                connection.release();
                if (err) {
                    console.error('Ошибка при обновлении элемента:', err);
                    return res.status(500).send('Ошибка сервера');
                }
                res.json({ status: "ok" });
            });
        });
    });
}

// Конфигурация multer для сохранения изображений
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true }); // Создаем папку, включая все промежуточные папки
        }
        cb(null, uploadPath); // Указываем папку для сохранения файлов
    },
    filename: function (req, file, cb) {
        // Генерируем уникальное имя для файла
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname)); 
    }
});

const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Только изображения разрешены!'), false);
    }
};

const upload = multer({ storage: storage, fileFilter: fileFilter });

const uploadImage = (req, res, next) => {
    upload.single('image')(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ error: 'Ошибка при загрузке файла!', details: err.message });
        } else if (err) {
            return res.status(500).json({ error: 'Ошибка сервера при загрузке файла!' });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'Файл не был загружен!' });
        }

        const inputFilePath = req.file.path;
        const outputFilePath = path.join(__dirname, 'uploads/uploads', req.file.filename);
        console.log(inputFilePath);
        console.log(outputFilePath);

        // Изменение размера изображения до 186x186 пикселей
        sharp(inputFilePath)
            .resize(186, 186)
            .toFile(outputFilePath, (err) => {
                if (err) {
                    console.log(err);
                    return res.status(500).json({ error: 'Ошибка при обработке изображения!' });
                }
                // Создаем полный URL для доступа к загруженному файлу
                const filePath = `http://localhost:5000/routes/uploads/uploads/${req.file.filename}`;
                res.status(200).json({ filePath: filePath });
            });
    });
};

function getItemPrice(req, res) {
    const { itemId } = req.query;

    if (!itemId) {
        return res.status(400).json({ error: 'Item ID is required' });
    }

    const selectQuery = 'SELECT name, price FROM Tovar WHERE id = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(selectQuery, [itemId], (err, result) => {
            connection.release();

            if (err) {
                console.error('Ошибка при запросе цены и имени товара:', err);
                return res.status(500).send('Ошибка сервера');
            }

            if (result && result.length > 0) {
                const { name, price } = result[0];
                res.status(200).json({ name, price });
            } else {
                res.status(404).json({ error: 'Товар не найден' });
            }
        });
    });
}

module.exports = {
    getTovar,
    deleteItem,
    addItem,
    updateItem,
    checkAdminAccessJson,
    uploadImage,
    getItemPrice
};
