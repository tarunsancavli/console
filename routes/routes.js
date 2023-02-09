const express = require('express');

const passport = require('passport');

const JWTOauth = passport.authenticate('jwt', { session : false });

const { signIn, signUp, changePassword, getAllUsers, getStats, getSessionlogs, getgroupdetails, getallgroups, createGroup, updateGroup, deleteGroup } = require('../controllers/controller');

const { userSignUpValidation, userSignInValidation, userPasswordValidation, userGroupValidation, userCreateGroupValidation, userUpdateGroupValidation} = require('../middlewares/validate');

const router = express.Router();

router.get('/signin', userSignInValidation, signIn);

router.post('/signup', userSignUpValidation, signUp);

router.put('/changepassword', userPasswordValidation, JWTOauth, changePassword);

router.get('/getall', getAllUsers);

router.get('/getstats', JWTOauth, getStats);

router.get('/getsessionlogs', JWTOauth, getSessionlogs);

router.get('/getgroupdetails', userGroupValidation, JWTOauth, getgroupdetails);

router.get('/getallgroups', JWTOauth, getallgroups);

router.post('/groups/creategroup', userCreateGroupValidation ,JWTOauth, createGroup);

router.patch('/groups/updategroup/:id', userUpdateGroupValidation, JWTOauth, updateGroup);

router.delete('/groups/deletegroup/:id', userUpdateGroupValidation, JWTOauth, deleteGroup);

module.exports = router;