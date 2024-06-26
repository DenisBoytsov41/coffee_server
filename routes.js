const express = require('express');
const router = express.Router();
const {loginAdmin,registerUser, loginUser, logoutUser, refreshToken,
    deleteRefreshToken, checkRefreshToken, updateTokensWithTheme, getUserByRefreshTokenHandler
 } = require('./routes/auth');
const {getTovar, deleteItem,addItem,updateItem, checkAdminAccessJson, uploadImage, getItemPrice} = require('./routes/items');
const {countBasket, updateBasket, getBasket, mergeBasket, processPayment} = require('./routes/basket');
const {updateLiked, getLiked, mergeLiked} = require('./routes/likes');
const {getInfoUser,updateInfoUser, sendMailReset, resetPass, checkLoginExistence, 
    comparePhoneNumberAndLogin, resetPassword, changePassword,getNewUsers, getOrderHistoryAdmin,
     getUserAccessRights, updateUserAccessLevel, sendNumberReset, getOrderHistory} = require('./routes/user');
const {getPaymentURL} = require('./routes/payment');
const {sendPasswordResetSMS , checkResetCode} = require('./routes/twilio');
const {addUserAdmin, updateUserAdmin, deleteAdminUser, checkAdminCredentials,
     updateNewUserAdminInfo, deleteNewUser, checkAdminCredentialsRefreshToken, deleteOrder, updateOrder} = require('./routes/admins');
const {getProductOfTheDay, getTop3Products7Days, getTop3ProductsMonth, getTop3ProductsDay} = require('./routes/popularProducts')

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
router.post('/changePassword', changePassword);
router.post('/checkAdminAccessJson', checkAdminAccessJson);

router.post('/addUserAdmin', addUserAdmin);
router.post('/updateUserAdmin', updateUserAdmin);
router.post('/deleteAdminUser', deleteAdminUser);
router.post('/checkAdminCredentials', checkAdminCredentials);
router.post('/updateNewUserAdminInfo', updateNewUserAdminInfo);
router.post('/deleteNewUser', deleteNewUser);
router.post('/checkAdminCredentialsRefreshToken', checkAdminCredentialsRefreshToken);

router.get('/getNewUsers', getNewUsers);
router.get('/getOrderHistory', getOrderHistory);
router.get('/getUserAccessRights', getUserAccessRights);
router.get('/sendNumberReset', sendNumberReset);
router.post('/updateUserAccessLevel', updateUserAccessLevel);
router.post('/uploadImage', uploadImage);
router.post('/processPayment', processPayment);
router.get('/getOrderHistoryAdmin', getOrderHistoryAdmin);
router.get('/getItemPrice', getItemPrice);
router.post('/deleteOrder', deleteOrder);
router.post('/updateOrder', updateOrder);
router.get('/product-of-the-day', getProductOfTheDay);
router.get('/top-3-products-7-days', getTop3Products7Days);
router.get('/top-3-products-month', getTop3ProductsMonth);
router.get('/top-3-products-day', getTop3ProductsDay);

module.exports = router;