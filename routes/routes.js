const express = require('express');

const JWTauth = require('../middlewares/auth');

const {signIn, signUp, changePassword, getAllUsers} = require('../controllers/controller');

const router = express.Router();

router.get('/signin', signIn);

router.post('/signup', signUp);

router.put('/changepassword', JWTauth, changePassword);

router.get('/getall', getAllUsers);

module.exports = router;