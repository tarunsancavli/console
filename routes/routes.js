const express = require('express');

const JWTauth = require('../middlewares/auth');

const { signIn, signUp, changePassword, getAllUsers, getStats, getSessionlogs, getgroupdetails, getallgroups } = require('../controllers/controller');

const { userSignUpValidation, userSignInValidation, userPasswordValidation, userGroupValidation} = require('../middlewares/validate');

const router = express.Router();

router.get('/signin', userSignInValidation, signIn);

router.post('/signup', userSignUpValidation, signUp);

router.put('/changepassword', userPasswordValidation, JWTauth, changePassword);

router.get('/getall', getAllUsers);

router.get('/getstats', JWTauth, getStats);

router.get('/getsessionlogs', JWTauth, getSessionlogs);

router.get('/getgroupdetails', userGroupValidation, JWTauth, getgroupdetails);

router.get('/getallgroups', JWTauth, getallgroups);

module.exports = router;