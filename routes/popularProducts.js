const pool = require('../pool');

const getCurrentDate = () => {
    return new Date().toISOString().slice(0, 10);
};

function getTopProducts(req, res, days, limit = 3) {
    const currentDate = getCurrentDate();
    const query = `
        SELECT items FROM OrderHistory
        WHERE DATEDIFF(?, date) <= ?
    `;

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(query, [currentDate, days], (err, result) => {
            if (err) {
                console.error('Ошибка при выполнении запроса к базе данных:', err);
                connection.release();
                return res.status(500).send('Ошибка сервера');
            }

            const productCounts = {};

            result.forEach(order => {
                const items = order.items.split(',');
                items.forEach(item => {
                    const [id, count] = item.split(':').map(Number);
                    if (!productCounts[id]) {
                        productCounts[id] = 0;
                    }
                    productCounts[id] += count;
                });
            });

            const topProductIds = Object.keys(productCounts)
                .sort((a, b) => productCounts[b] - productCounts[a])
                .slice(0, limit);

            if (topProductIds.length === 0) {
                connection.release();
                return res.status(404).send('Нет данных за указанный период');
            }

            const topProductsQuery = `SELECT * FROM Tovar WHERE id IN (${topProductIds.join(',')})`;

            connection.query(topProductsQuery, (err, products) => {
                connection.release();
                if (err) {
                    console.error('Ошибка при выполнении запроса к базе данных:', err);
                    return res.status(500).send('Ошибка сервера');
                }

                console.log(`Топ ${topProductIds.length} продуктов успешно получены за последние ${days} дней`);

                products.forEach(product => {
                    console.log(`Название товара: ${product.name}, Количество: ${productCounts[product.id]}`);
                });

                res.json(products);
            });
        });
    });
}

function getProductOfTheDay(req, res) {
    const currentDate = getCurrentDate();
    const query = `
        SELECT items FROM OrderHistory
        WHERE DATEDIFF(?, date) = 0
    `;

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Ошибка при получении соединения из пула:', err);
            return res.status(500).send('Ошибка сервера');
        }

        connection.query(query, [currentDate], (err, result) => {
            if (err) {
                console.error('Ошибка при выполнении запроса к базе данных:', err);
                connection.release();
                return res.status(500).send('Ошибка сервера');
            }

            if (result.length === 0) {
                connection.release();
                return res.status(404).send('Сегодня заказов не было');
            }

            const productCounts = {};

            result.forEach(order => {
                const items = order.items.split(',');
                items.forEach(item => {
                    const [id, count] = item.split(':').map(Number);
                    if (!productCounts[id]) {
                        productCounts[id] = 0;
                    }
                    productCounts[id] += count;
                });
            });

            const productIds = Object.keys(productCounts);

            if (productIds.length === 0) {
                connection.release();
                return res.status(404).send('Нет данных за текущий день');
            }

            const randomProductId = productIds[Math.floor(Math.random() * productIds.length)];

            const productQuery = `SELECT * FROM Tovar WHERE id = ?`;

            connection.query(productQuery, [randomProductId], (err, product) => {
                connection.release();
                if (err) {
                    console.error('Ошибка при выполнении запроса к базе данных:', err);
                    return res.status(500).send('Ошибка сервера');
                }

                console.log("Продукт дня успешно получен");
                console.log(`Название товара: ${product[0].name}, Количество: ${productCounts[randomProductId]}`);

                res.json(product);
            });
        });
    });
}

function getTop3Products7Days(req, res) {
    getTopProducts(req, res, 7, 3);
}
function getTop3ProductsDay(req, res) {
    getTopProducts(req, res, 1, 3);
}

function getTop3ProductsMonth(req, res) {
    getTopProducts(req, res, 30, 3);
}

module.exports = {
    getProductOfTheDay,
    getTop3Products7Days,
    getTop3ProductsMonth,
    getTop3ProductsDay
};
