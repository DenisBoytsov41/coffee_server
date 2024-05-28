const express = require('express');
const router = express.Router();
const {loginAdmin,registerUser, loginUser, logoutUser, refreshToken,
    deleteRefreshToken, checkRefreshToken, updateTokensWithTheme, getUserByRefreshTokenHandler
 } = require('./routes/auth');
const {getTovar, deleteItem,addItem,updateItem} = require('./routes/items');
const {countBasket, updateBasket, getBasket, mergeBasket} = require('./routes/basket');
const {updateLiked, getLiked, mergeLiked} = require('./routes/likes');
const {getInfoUser,updateInfoUser, sendMailReset, resetPass, checkLoginExistence, 
    comparePhoneNumberAndLogin, resetPassword} = require('./routes/user');
const {getPaymentURL} = require('./routes/payment');
const {sendPasswordResetSMS , checkResetCode} = require('./routes/twilio');

router.post('/loginAdmin', loginAdmin);
router.post('/checkUser', loginUser);
router.post('/RegUser', registerUser);
router.get('/tovar', getTovar);
router.post('/deleteItem', deleteItem);
router.post('/addItem', addItem);
router.post('/UpdateItem', updateItem);
router.post('/CountBasket', countBasket);
router.post('/UpdateBasket', updateBasket);
router.post('/MergeBasket', mergeBasket);
router.post('/GetBasket', getBasket);
router.post('/UpdateLiked', updateLiked);
router.post('/MergeLiked', mergeLiked);
router.post('/GetLiked', getLiked);
router.post('/GetPaymentURL', getPaymentURL);
router.post('/GetInfoUser', getInfoUser);
router.post('/UpdateInfoUser', updateInfoUser);
router.post('/SendMailReset', sendMailReset);
router.post('/ResetPass', resetPass);
router.get('/checkToken', getUserByRefreshTokenHandler);
//router.post('/login', loginUser);
router.post('/logout', logoutUser);
router.post('/refreshToken/:token', refreshToken);
router.post('/deleteRefreshToken', deleteRefreshToken);
router.post('/checkRefreshToken', checkRefreshToken);
router.post('/updateTokensWithTheme', updateTokensWithTheme);
router.post('/sendPasswordResetSMS', sendPasswordResetSMS);
router.post('/checkLoginExistence', checkLoginExistence);
router.post('/comparePhoneNumberAndLogin', comparePhoneNumberAndLogin);
router.post('/checkResetCode', checkResetCode);
router.post('/resetPassword', resetPassword);



module.exports = router;
