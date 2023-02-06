const joi = require("joi");
const errorFunction = require('../utils/error');

const signUpValidation = joi.object({
    firstName: joi.string().alphanum().min(3).max(25).trim(true).required(),
    lastName: joi.string().alphanum().min(3).max(25).trim(true).required(),
    email: joi.string().email().trim(true).required(),
    password: joi.string().min(8).trim(true).required()
});

const signInValidation = joi.object({
    email: joi.string().email().trim(true).required(),
    password: joi.string().trim(true).required()
});

const changePasswordValidation = joi.object({
    email: joi.string().email().trim(true).required(),
    password: joi.string().min(8).trim(true).required(),
    newPassword: joi.string().min(8).trim(true).required(),
    confirmPassword: joi.string().min(8).trim(true).required()
});

const groupValidation = joi.object({
    groupType: joi.number().integer(),
});

const createGroupValidation = joi.object({
    groupName: joi.string().alphanum().min(3).max(25).trim(true).required(),
    description: joi.string().alphanum().min(3).max(25).trim(true).required(),
    active:joi.boolean().required(),
    deleted:joi.boolean().required(),
    groupType:joi.number().integer().required(),
});

const updateGroupValidation = joi.object({
    groupId: joi.string().alphanum().min(24).max(24).trim(true).required(),
});

const userSignUpValidation = async (req, res, next) => {
    const payload = {
        firstName: req.body.first_name,
        lastName: req.body.last_name,
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

const userCreateGroupValidation = async (req,res,next) => {
    const payload = {
        groupName: req.body.group_name,
        description: req.body.description,
        active: req.body.active,
        deleted: req.body.deleted,
        groupType: req.body.group_type,
    };
    const { error } = createGroupValidation.validate(payload);
    if (error) {
        res.status(406).json(errorFunction(true, `Error in User Data : ${error.message}`))
    } else {
        next();
    }
}

const userUpdateGroupValidation = async (req, res, next) => {
    const payload = {
        groupId: req.params['id']
    };
    const { error } = updateGroupValidation.validate(payload);
    if (error) {
        res.status(406).json(errorFunction(true, `Error in User Data : ${error.message}`))
    } else {
        next();
    }
}

const userDeleteGroupValidation = async (req, res, next) => {
    const payload = {
        groupId: req.params['id']
    };
    const { error } = updateGroupValidation.validate(payload);
    if (error) {
        res.status(406).json(errorFunction(true, `Error in User Data : ${error.message}`))
    } else {
        next();
    }
}



module.exports = { userSignUpValidation, userSignInValidation, userPasswordValidation, userGroupValidation, userCreateGroupValidation, userUpdateGroupValidation, userDeleteGroupValidation };