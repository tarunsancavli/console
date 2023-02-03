const express = require('express');

const JWTauth = require('../middlewares/auth');

const { signIn, signUp, changePassword, getAllUsers, getStats, getSessionlogs, getgroupdetails, getallgroups, createGroup, updateGroup, deleteGroup } = require('../controllers/controller');

const { userSignUpValidation, userSignInValidation, userPasswordValidation, userGroupValidation, userCreateGroupValidation, userUpdateGroupValidation} = require('../middlewares/validate');

const router = express.Router();

router.get('/signin', userSignInValidation, signIn);

router.post('/signup', userSignUpValidation, signUp);

router.put('/changepassword', userPasswordValidation, JWTauth, changePassword);

router.get('/getall', getAllUsers);

router.get('/getstats', JWTauth, getStats);

router.get('/getsessionlogs', JWTauth, getSessionlogs);

router.get('/getgroupdetails', userGroupValidation, JWTauth, getgroupdetails);

router.get('/getallgroups', JWTauth, getallgroups);

router.post('/groups/creategroup', userCreateGroupValidation ,JWTauth, createGroup);

router.patch('/groups/updategroup/:id', userUpdateGroupValidation, JWTauth, updateGroup);

router.delete('/groups/deletegroup/:id', userUpdateGroupValidation, JWTauth, deleteGroup);

module.exports = router;