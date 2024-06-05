const express = require('express');
const userController = require('../controllers/user.controller');
const authJWT = require('../middlewares/authJWT')
const router = express.Router();

router.route('/signup').post(userController.registerUser);
router.route('/login').post(userController.login);
router.route('/logout').post(authJWT.verifyToken, userController.logout);
router.route('/profile').get(authJWT.verifyToken, userController.userProfile);

module.exports = router;