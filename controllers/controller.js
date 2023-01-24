const jwt = require('jsonwebtoken');

const bcrypt = require('bcryptjs');

require('dotenv').config();

const { getDB } = require('../config/db');

async function getAllUsers(req, res) {
    const db = getDB();
    const users = await db.collection('users').find({}).toArray();
    res.status(200).send(users);
}

async function signIn(req, res) {
    const db = getDB();
    const email = req.query.email;
    const password = req.query.password;

    const user = await db.collection('users').findOne({ email: email });

    if (!user) {
        res.status(404).json({
            message: 'incorrect email'
        })
    } else {
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                console.error(err);
            } else {
                if (result) {
                    const payload = { user: user };
                    jwt.sign(payload, process.env.JWT_SECRET, (err, token) => {
                        res.status(200).json({
                            message: 'user signed in successfully',
                            token: token
                        })
                    });
                }
                else {
                    res.status(401).json({
                        message: 'incorrect password'
                    })
                }
            }
        })
    }
}

async function signUp(req, res) {
    const user = req.body;
    const db = getDB();
    if (!(user.first_name && user.last_name && user.email && user.password)) {
        res.status(403).json({
            message: "invalid credentials"
        })
    } else {
        const oldUser = await db.collection('users').findOne({ email: user.email });
        console.log(oldUser);
        if (oldUser) {
            res.status(400).json({
                message: 'Another account exists with the same email'
            })
        }
        else {
            try {
                const pass = user.password;

                const salt = await bcrypt.genSalt(10);
                const hashPass = await bcrypt.hash(pass, salt);

                user.password = hashPass;

                await db.collection('users').insertOne(user);
                res.status(200).json({
                    message: 'user signed up successfully'
                })
                console.log(user);
            } catch (err) {
                console.error(err);
            }
        }
    }

}

async function changePassword(req, res) {
    try {
        const email = req.query.email;
        const password = req.query.password;
        const newPassword = req.query.new_password;
        const confirmPassword = req.query.confirm_password;

        const db = getDB();

        if (!(newPassword && confirmPassword && password && email)) {
            res.status(404).json({
                message: "please enter all fields"
            })
        }
        else {
            if (newPassword !== confirmPassword) {
                res.status(403).json({
                    message: 'confirm_password  do not match'
                })
            } else {
                const user = await db.collection('users').findOne({ email: email });
                if (!user) {
                    res.status(404).json({
                        message: 'No user found'
                    })
                } else {
                    bcrypt.compare(password, user.password, async (err, result) => {
                        if (err) {
                            console.error(err);
                        }
                        else {
                            if (result) {
                                const salt = await bcrypt.genSalt(10);
                                const passwordHash = await bcrypt.hash(newPassword, salt);

                                const updateDocument = {
                                    $set: {
                                        password: passwordHash,
                                    },
                                }

                                await db.collection('users').updateOne(user, updateDocument);
                                console.log(user);
                                res.status(200).json({
                                    message: "your password has been changed successfully"
                                })
                            }
                            else {
                                res.status(403).json({
                                    message: 'incorrect password'
                                })
                            }
                        }
                    })
                }
            }
        }
    } catch (err) {
        console.error(err);
    }
}

module.exports = { signIn, signUp, changePassword, getAllUsers };