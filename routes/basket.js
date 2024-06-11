//const connsql = require('../database');
const pool = require('../pool');
const { v4: uuidv4 } = require('uuid');

function countBasket(req, res) {
    if (!req.body.basket || req.body.basket.trim() === '') {
        return res.json({ basket: 0, count: 0 });
    }
    
    const strArr = req.body.basket.split(",");
    const itemMap = new Map();
    let totalCost = 0;
    let processedItems = 0;

    // Обработка каждого элемента корзины
    strArr.forEach((item, index) => {
        const [id, quantity] = item.split(":");
        const itemId = parseInt(id);
        const origQuantity = parseInt(quantity);
        
        // Проверка, что id больше 0 и quantity в допустимом диапазоне
        if (itemId > 0 && origQuantity >= 1) {
            // Округляем quantity до 1000, если оно больше 1000
            const itemQuantity = Math.min(origQuantity, 1000);

            // Получаем цену товара из базы данных
            const query = 'SELECT price * ? AS cost FROM Tovar WHERE id = ?';
            pool.getConnection((getConnectionErr, connection) => {
                if (getConnectionErr) {
                    console.error('Ошибка при получении соединения из пула: ', getConnectionErr);
                    res.status(500).json({ error: 'Ошибка сервера' });
                    return;
                }

                connection.query(query, [itemQuantity, itemId], (err, result) => {
                    connection.release(); // Освобождаем соединение после использования
                    if (err) {
                        console.error('Ошибка при выполнении запроса к базе данных:', err);
                        res.status(500).json({ error: 'Ошибка сервера' });
                        return;
                    }

                    // Если найдена цена, добавляем стоимость товара к общей стоимости
                    if (result.length > 0) {
                        const cost = parseFloat(result[0].cost);
                        totalCost += cost;

                        // Добавляем количество товара к существующему или создаем новую запись
                        if (itemMap.has(itemId)) {
                            itemMap.set(itemId, itemMap.get(itemId) + itemQuantity);
                        } else {
                            itemMap.set(itemId, itemQuantity);
                        }
                    }

                    processedItems++;

                    if (processedItems === strArr.length) {
                        const updatedBasket = [...itemMap].map(([id, quantity]) => `${id}:${quantity}`).join(",");
                        console.log("----------");
                        console.log(updatedBasket);
                        console.log(totalCost);
                        res.json({ basket: updatedBasket, count: totalCost });
                    }
                });
            });
        } else {
            console.error('Invalid id or quantity:', itemId, origQuantity);
            processedItems++;
            if (processedItems === strArr.length) {
                res.status(400).send('Invalid id or quantity');
            }
        }
    });
}

function mergeBasket(req, res) {
    console.log("мы в методе mergeBasket");
    const login = req.body.login.toLowerCase();
    const itemMap = new Map(); // Используем Map для облегчения поиска и обновления элементов

    // Проверяем, есть ли такой пользователь в таблице newusers
    const queryNewUsers = 'SELECT * FROM newusers WHERE login = ?';
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            res.status(500).send('Ошибка сервера');
            return;
        }

        connection.query(queryNewUsers, [login], (err, resultNewUsers) => {
            connection.release(); // Освобождаем соединение после использования

            if (err) {
                console.error('Ошибка при выполнении запроса к таблице newusers:', err);
                res.status(500).send('Ошибка сервера');
                return;
            }

            if (resultNewUsers.length === 0) {
                // Пользователь не найден, возвращаем 0
                res.json({ res: 0 });
            } else {
                // Обрабатываем входные элементы
                let inputItems = req.body.items.split(',');
                inputItems.forEach(inputItem => {
                    let parts = inputItem.split(':');
                    let itemId = parseInt(parts[0]);
                    let origItemCount = parseInt(parts[1]);
                    // Округляем количество товара до 1000, если оно больше 1000
                    let itemCount = Math.min(origItemCount, 1000);
                    if (itemId >= 1 && itemCount >= 0) {
                        if (itemMap.has(itemId)) {
                            itemMap.set(itemId, itemCount);
                        } else {
                            itemMap.set(itemId, itemCount);
                        }
                    }
                });

                // Проверяем, есть ли пользователь в таблице usersItems
                const queryUsersItems = 'SELECT * FROM usersItems WHERE login = ?';
                pool.getConnection((err, connection) => {
                    if (err) {
                        console.error('Ошибка при получении соединения из пула:', err);
                        res.status(500).send('Ошибка сервера');
                        return;
                    }

                    connection.query(queryUsersItems, [login], (err, resultUsersItems) => {
                        connection.release(); // Освобождаем соединение после использования

                        if (err) {
                            console.error('Ошибка при выполнении запроса к таблице usersItems:', err);
                            res.status(500).send('Ошибка сервера');
                            return;
                        }

                        if (resultUsersItems.length > 0) {
                            // Если пользователь уже есть в таблице, обновляем корзину
                            let existingItems = resultUsersItems[0].korzina.split(',');
                            existingItems.forEach(existingItem => {
                                let parts = existingItem.split(':');
                                let itemId = parseInt(parts[0]);
                                let itemCount = parseInt(parts[1]);
                                if (itemMap.has(itemId)) {
                                    itemMap.set(itemId, itemMap.get(itemId) + itemCount);
                                } else {
                                    itemMap.set(itemId, itemCount);
                                }
                            });
                        }

                        // После объединения, проверяем, есть ли элементы, количество которых больше 1000
                        itemMap.forEach((itemCount, itemId) => {
                            if (itemCount > 1000) {
                                itemMap.set(itemId, 1000); // Устанавливаем количество равное 1000
                            }
                        });

                        let updatedKorzina = [...itemMap].map(([itemId, itemCount]) => `${itemId}:${itemCount}`).join(',');
                        let updateQuery;
                        let queryParams;
                        if (resultUsersItems.length > 0) {
                            updateQuery = 'UPDATE usersItems SET korzina = ? WHERE login = ?';
                            queryParams = [updatedKorzina, req.body.login.toLowerCase()];
                        } else {
                            updateQuery = 'INSERT INTO usersItems (login, korzina) VALUES (?, ?)';
                            queryParams = [req.body.login.toLowerCase(), updatedKorzina];
                        }

                        pool.getConnection((err, connection) => {
                            if (err) {
                                console.error('Ошибка при получении соединения из пула:', err);
                                res.status(500).send('Ошибка сервера');
                                return;
                            }

                            connection.query(updateQuery, queryParams, (err, result) => {
                                connection.release(); // Освобождаем соединение после использования

                                if (err) {
                                    console.error('Ошибка при выполнении запроса на обновление корзины:', err);
                                    res.status(500).send('Ошибка сервера');
                                    return;
                                }

                                res.json({ res: updatedKorzina });
                            });
                        });
                    });
                });
            }
        });
    });
}

function updateBasket(req, res) {
    console.log("мы в методе updateBasket");
    const login = req.body.login.toLowerCase();
    const itemMap = new Map(); // Используем Map для облегчения поиска и обновления элементов

    // Проверяем, есть ли такой пользователь в таблице newusers
    const queryNewUsers = 'SELECT * FROM newusers WHERE login = ?';
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            res.status(500).send('Ошибка сервера');
            return;
        }

        connection.query(queryNewUsers, [login], (err, resultNewUsers) => {
            connection.release(); // Освобождаем соединение после использования

            if (err) {
                console.error('Ошибка при выполнении запроса к таблице newusers:', err);
                res.status(500).send('Ошибка сервера');
                return;
            }

            if (resultNewUsers.length === 0) {
                // Пользователь не найден, возвращаем 0
                res.json({ res: 0 });
            } else {
                // Обрабатываем входные элементы
                let inputItems = req.body.items.split(',');
                console.log(inputItems);
                inputItems.forEach(inputItem => {
                    let parts = inputItem.split(':');
                    let itemId = parseInt(parts[0]);
                    let itemCount = parseInt(parts[1]);
                    if (itemId >= 1 && itemCount >= 0 && itemCount <= 1000) {
                        if (itemMap.has(itemId)) {
                            itemMap.set(itemId, itemCount);
                        } else {
                            itemMap.set(itemId, itemCount);
                        }
                    }
                });
                // Обновляем строку корзины
                let updatedKorzina = [...itemMap].map(([itemId, itemCount]) => `${itemId}:${itemCount}`).join(',');

                // Проверяем, есть ли пользователь в таблице usersItems
                const queryUsersItems = 'SELECT * FROM usersItems WHERE login = ?';
                pool.getConnection((err, connection) => {
                    if (err) {
                        console.error('Ошибка при получении соединения из пула:', err);
                        res.status(500).send('Ошибка сервера');
                        return;
                    }

                    connection.query(queryUsersItems, [login], (err, resultUsersItems) => {
                        connection.release(); // Освобождаем соединение после использования

                        if (err) {
                            console.error('Ошибка при выполнении запроса к таблице usersItems:', err);
                            res.status(500).send('Ошибка сервера');
                            return;
                        }

                        let updateQuery;
                        let queryParams;
                        if (resultUsersItems.length > 0) {
                            // Если пользователь уже есть в таблице, обновляем корзину
                            updateQuery = 'UPDATE usersItems SET korzina = ? WHERE login = ?';
                            queryParams = [updatedKorzina, req.body.login.toLowerCase()];
                        } else {
                            // Если пользователя нет в таблице, создаем новую запись
                            updateQuery = 'INSERT INTO usersItems (login, korzina) VALUES (?, ?)';
                            queryParams = [req.body.login.toLowerCase(), updatedKorzina];
                        }

                        pool.getConnection((err, connection) => {
                            if (err) {
                                console.error('Ошибка при получении соединения из пула:', err);
                                res.status(500).send('Ошибка сервера');
                                return;
                            }

                            connection.query(updateQuery, queryParams, (err, result) => {
                                connection.release(); // Освобождаем соединение после использования

                                if (err) {
                                    console.error('Ошибка при выполнении запроса на обновление корзины:', err);
                                    res.status(500).send('Ошибка сервера');
                                    return;
                                }

                                // Возвращаем обновленное значение корзины
                                res.json({ res: updatedKorzina });
                            });
                        });
                    });
                });
            }
        });
    });
}
function processPayment(req, res) {
    const { login, refreshToken, email, basket } = req.body;
    let userLogin = login || "";

    // Если пришел email, значит пользователь не авторизован, используем email для идентификации
    if (email) {
        // Проверяем, был ли передан корзина
        if (!basket) {
            res.status(400).send('Отсутствует корзина в запросе');
            return;
        }
    
        // Обработка корзины и вычисление общей цены
        let total = 0;
        let items = {};
    
        basket.split(',').forEach(item => {
            const [itemId, itemCount] = item.split(':');
            items[itemId] = parseInt(itemCount);
        });
    
        // Вычисляем общую цену товаров в корзине
        Promise.all(Object.entries(items).map(([itemId, itemCount]) => {
            return new Promise((resolve, reject) => {
                const queryItemPrice = 'SELECT price FROM Tovar WHERE id = ?';
                pool.query(queryItemPrice, [itemId], (err, resultItemPrice) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    if (resultItemPrice.length > 0) {
                        const price = resultItemPrice[0].price;
                        total += price * itemCount;
                    }
                    resolve();
                });
            });
        })).then(() => {
            const orderId = generateOrderId(); // Генерируем orderId
            const currentDate = new Date().toISOString().slice(0, 10); // Получаем текущую дату
            const status = 'В обработке';
            const orderItems = Object.keys(items).map(itemId => `${itemId}:${items[itemId]}`).join(',');
    
            // Вставляем заказ в таблицу OrderHistory
            const insertOrderQuery = 'INSERT INTO OrderHistory (login, orderId, date, status, total, items) VALUES (?, ?, ?, ?, ?, ?)';
            pool.query(insertOrderQuery, [email, orderId, currentDate, status, total, orderItems], (err, result) => {
                if (err) {
                    console.error('Ошибка при выполнении запроса на добавление заказа:', err);
                    res.status(500).send('Ошибка сервера');
                    return;
                }
                res.json({ orderId, total });
            });
        }).catch(error => {
            console.error('Ошибка при обработке товаров корзины:', error);
            res.status(500).send('Ошибка сервера');
        });
    }
     else {
        // Если пришел refreshToken или login, смотрим в таблице newusers
        const queryNewUsers = `SELECT * FROM ${refreshToken ? 'UserToken' : 'newusers'} WHERE ${refreshToken ? 'refreshToken' : 'login'} = ?`;
        console.log(queryNewUsers);
        pool.query(queryNewUsers, [refreshToken || login], (err, resultNewUsers) => {
            if (err) {
                console.error('Ошибка при выполнении запроса к таблице newusers:', err);
                res.status(500).send('Ошибка сервера');
                return;
            }

            if (resultNewUsers.length === 0) {
                res.status(404).send('Пользователь не найден');
            } else {
                const userLogin = refreshToken ? resultNewUsers[0].user : resultNewUsers[0].login;
                const queryUserItems = 'SELECT korzina FROM usersItems WHERE login = ?';
                pool.query(queryUserItems, [userLogin], (err, resultUserItems) => {
                    if (err) {
                        console.error('Ошибка при выполнении запроса к таблице usersItems:', err);
                        res.status(500).send('Ошибка сервера');
                        return;
                    }

                    let items = {};
                    if (resultUserItems.length > 0) {
                        const userBasket = resultUserItems[0].korzina;
                        userBasket.split(',').forEach(item => {
                            const [itemId, itemCount] = item.split(':');
                            items[itemId] = parseInt(itemCount);
                        });
                    }

                    let total = 0;
                    Promise.all(Object.entries(items).map(([itemId, itemCount]) => {
                        return new Promise((resolve, reject) => {
                            const queryItemPrice = 'SELECT price FROM Tovar WHERE id = ?';
                            pool.query(queryItemPrice, [itemId], (err, resultItemPrice) => {
                                if (err) {
                                    reject(err);
                                    return;
                                }
                                if (resultItemPrice.length > 0) {
                                    const price = resultItemPrice[0].price;
                                    total += price * itemCount;
                                }
                                resolve();
                            });
                        });
                    })).then(() => {
                        const orderId = generateOrderId(); 
                        const currentDate = new Date().toISOString().slice(0, 10); 
                        const status = 'В обработке';
                        const orderItems = Object.keys(items).map(itemId => `${itemId}:${items[itemId]}`).join(',');
                        
                        const insertOrderQuery = 'INSERT INTO OrderHistory (login, orderId, date, status, total, items) VALUES (?, ?, ?, ?, ?, ?)';
                        pool.query(insertOrderQuery, [userLogin, orderId, currentDate, status, total, orderItems], (err, result) => {
                            if (err) {
                                console.error('Ошибка при выполнении запроса на добавление заказа:', err);
                                res.status(500).send('Ошибка сервера');
                                return;
                            }
                            res.json({ orderId, total });
                        });
                    }).catch(error => {
                        console.error('Ошибка при обработке товаров корзины:', error);
                        res.status(500).send('Ошибка сервера');
                    });
                });
            }
        });
    }
}

function getBasket(req, res) {
    const login = req.body.login.toLowerCase();

    // Проверяем, есть ли такой пользователь в таблице newusers
    const queryNewUsers = 'SELECT * FROM newusers WHERE login = ?';
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            res.status(500).send('Ошибка сервера');
            return;
        }

        connection.query(queryNewUsers, [login], (err, resultNewUsers) => {
            connection.release(); // Освобождаем соединение после использования

            if (err) {
                console.error('Ошибка при выполнении запроса к таблице newusers:', err);
                res.status(500).send('Ошибка сервера');
                return;
            }

            if (resultNewUsers.length === 0) {
                // Пользователь не найден, возвращаем пустую корзину
                res.json({ res: "" });
            } else {
                // Пользователь найден, ищем его корзину в таблице usersItems
                const queryUsersItems = 'SELECT korzina FROM usersItems WHERE login = ?';
                pool.getConnection((err, connection) => {
                    if (err) {
                        console.error('Ошибка при получении соединения из пула:', err);
                        res.status(500).send('Ошибка сервера');
                        return;
                    }

                    connection.query(queryUsersItems, [login], (err, resultUsersItems) => {
                        connection.release(); // Освобождаем соединение после использования

                        if (err) {
                            console.error('Ошибка при выполнении запроса к таблице usersItems:', err);
                            res.status(500).send('Ошибка сервера');
                            return;
                        }

                        if (resultUsersItems.length === 0) {
                            // Пользователь не найден в таблице usersItems, создаем новую запись для него с пустой корзиной
                            const insertEmptyBasketQuery = 'INSERT INTO usersItems (login, korzina) VALUES (?, ?)';
                            pool.getConnection((err, connection) => {
                                if (err) {
                                    console.error('Ошибка при получении соединения из пула:', err);
                                    res.status(500).send('Ошибка сервера');
                                    return;
                                }

                                connection.query(insertEmptyBasketQuery, [login, ''], (err, result) => {
                                    connection.release(); // Освобождаем соединение после использования

                                    if (err) {
                                        console.error('Ошибка при создании пустой корзины:', err);
                                        res.status(500).send('Ошибка сервера');
                                        return;
                                    }

                                    // Возвращаем пустую корзину
                                    res.json({ res: "" });
                                });
                            });
                        } else {
                            // Обработка корзины
                            let korzina = resultUsersItems[0].korzina;
                            let items = korzina.split(',');
                            let updatedItems = [];
                            items.forEach(item => {
                                let parts = item.split(':');
                                let itemId = parseInt(parts[0]);
                                let itemCount = parseInt(parts[1]);
                                if (itemId > 0 && itemCount > 0 && itemCount <= 1000) {
                                    updatedItems.push(`${itemId}:${Math.min(itemCount, 1000)}`);
                                }
                            });
                             // Составляем строку снова
                            let updatedKorzina = updatedItems.join(',');

                            // Обновляем корзину в базе данных
                            const updateQuery = 'UPDATE usersItems SET korzina = ? WHERE login = ?';
                            pool.getConnection((err, connection) => {
                                if (err) {
                                    console.error('Ошибка при получении соединения из пула:', err);
                                    res.status(500).send('Ошибка сервера');
                                    return;
                                }

                                connection.query(updateQuery, [updatedKorzina, login], (err, result) => {
                                    connection.release(); // Освобождаем соединение после использования

                                    if (err) {
                                        console.error('Ошибка при обновлении корзины:', err);
                                        res.status(500).send('Ошибка сервера');
                                        return;
                                    }

                                    // Возвращаем обновленное значение корзины
                                    res.json({ res: updatedKorzina });
                                });
                            });
                        }
                    });
                });
            }
        });
    });
}
function generateOrderId() {
    return uuidv4();
}

module.exports = {
    countBasket,
    updateBasket,
    getBasket,
    mergeBasket,
    processPayment
};
