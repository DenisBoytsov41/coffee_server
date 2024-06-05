const express = require('express');
const cors = require('cors');
const routes = require('./routes');
const fs = require('fs');
const https = require('https');
const bodyParser = require('body-parser');
const schedule = require('node-schedule');
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({ origin: "*" }));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
  });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.get('/routes/uploads/:filename', (req, res) => {
  const { filename } = req.params;
  res.sendFile(path.join(__dirname, 'routes/uploads', filename));
});
app.get('/routes/uploads/uploads/:filename', (req, res) => {
  const { filename } = req.params;
  res.sendFile(path.join(__dirname, 'routes/uploads/uploads', filename));
});
app.get('/uploads/:filename', (req, res) => {
  const { filename } = req.params;
  res.sendFile(path.join(__dirname, 'uploads', filename));
});
/*const options = {
    key: fs.readFileSync('keys/PRIV.pem'),
    cert: fs.readFileSync('keys/CERT.pem'),
};*/

//const server = https.createServer(options, app);

app.use('/api', routes);
const removeExpiredTokens = () => {
    const moment = require('moment-timezone');
    const currentDate = moment.tz('Europe/Moscow').format('YYYY-MM-DD HH:mm:ss');
    console.log(currentDate);
  
    const deleteQuery = 'DELETE FROM UserToken WHERE expiresIn < ?';
    db.query(deleteQuery, [currentDate], (err, result) => {
      if (err) {
        console.error('Ошибка при удалении устаревших токенов из базы данных: ', err);
      } else {
        console.log('Устаревшие токены успешно удалены');
      }
    });
  };
  
  const job = schedule.scheduleJob('*/5 * * * *', () => {
    console.log('Выполнение задачи по удалению устаревших токенов...');
    removeExpiredTokens();
  });

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;