const joi = require("joi");
const errorFunction = require('../utils/error');

const signUpValidation = joi.object({
    firstName: joi.string().alphanum().min(3).max(25).trim(true).required(),
    lastName: joi.string().alphanum().min(3).max(25).trim(true).required(),
    email: joi.string().email().trim(true).required(),
    password: joi.string().min(8).trim(true).required()
        .default([]),
    is_active: joi.boolean().default(true),
});

const signInValidation = joi.object({
    email: joi.string().email().trim(true).required(),
    password: joi.string().trim(true).required()
        .default([]),
    is_active: joi.boolean().default(true),
});

const changePasswordValidation = joi.object({
    email: joi.string().email().trim(true).required(),
    password: joi.string().min(8).trim(true).required(),
    newPassword: joi.string().min(8).trim(true).required(),
    confirmPassword: joi.string().min(8).trim(true).required()
        .default([]),
    is_active: joi.boolean().default(true),
});

const groupValidation = joi.object({
    groupType: joi.number().integer(),
    is_active: joi.boolean().default(true),
});

const userSignUpValidation = async (req, res, next) => {
    const payload = {
        firstName: req.body.first_Name,
        lastName: req.body.last_Name,
        email: req.body.email,
        password: req.body.password,
    };

    const { error } = signUpValidation.validate(payload);
    if (error) {
        res.status(406);
        return res.json(
            errorFunction(true, `Error in User Data : ${error.message}`)
        );
    } else {
        next();
    }
};

const userSignInValidation = async (req, res, next) => {
    const payload = {
        email: req.query.email,
        password: req.query.password
    };

    const { error } = signInValidation.validate(payload);
    if (error) {
        res.status(406).json(errorFunction(true, `Error in User Data : ${error.message}`))
    } else {
        next();
    }
};

const userPasswordValidation = async (req, res, next) => {
    const payload = {
        email: req.query.email,
        password: req.query.password,
        newPassword: req.query.new_password,
        confirmPassword: req.query.confirm_password
    }
    const { error } = changePasswordValidation.validate(payload);
    if (error) {
        res.status(406).json(errorFunction(true, `Error in User Data : ${error.message}`))
    } else {
        next();
    }
}

const userGroupValidation = async (req, res, next) => {
    const payload = {
        groupType: req.query.group_type
    }
    const { error } = groupValidation.validate(payload);
    if (error) {
        res.status(406).json(errorFunction(true, `Error in User Data : ${error.message}`))
    } else {
        next();
    }
}



module.exports = { userSignUpValidation, userSignInValidation, userPasswordValidation, userGroupValidation };