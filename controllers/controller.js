const jwt = require('jsonwebtoken');

const errorFunction = require('../utils/error');

const moment = require('moment');

const bcrypt = require('bcryptjs');

require('dotenv').config();

const { getDB } = require('../config/db');

const { ObjectId } = require('mongodb');

async function getAllUsers(req, res) {
    try {
        const db = getDB();
        const users = await db.collection('users').find({}).toArray();
        res.status(200).json(errorFunction(false, "Sending all users", users));
    } catch (err) {
        console.error(err);
        res.status(400).json(errorFunction(true, "Error listing all users"))
    }
}

async function signIn(req, res) {
    try {
        const db = getDB();
        const email = req.query.email;
        const password = req.query.password;

        const user = await db.collection('users').findOne({ email: email });

        if (!user) {
            res.status(404).json(errorFunction(true, "incorrect email"))
        } else {
            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    console.error(err);
                    res.status(400).json(errorFunction(true, "Error Authenticating Password"));
                } else {
                    if (result) {
                        const payload = { user: user };
                        jwt.sign(payload, process.env.JWT_SECRET, (err, token) => {
                            res.status(200).json(errorFunction(false, "user signed in successfully", `user signed in successfully,token: ${token}`))
                        });
                    }
                    else {
                        res.status(401).json(errorFunction(true, "Incorrect password"));
                    }
                }
            })
        }
    } catch (err) {
        console.error(err);
        res.status(400).json(errorFunction(true, "Error Signing In"));
    }
}

async function signUp(req, res) {
    const user = req.body;
    const db = getDB();
    const oldUser = await db.collection('users').findOne({ email: user.email });
    if (oldUser) {
        res.status(403).json(errorFunction(true, "User already exists"));
    }
    else {
        try {
            const pass = user.password;

            const salt = await bcrypt.genSalt(10);
            const hashPass = await bcrypt.hash(pass, salt);

            user.password = hashPass;

            await db.collection('users').insertOne(user);
            res.status(200).json(errorFunction(false, "user Created Successfully", user));
        } catch (err) {
            res.status(400).json(errorFunction(true, "Error adding user"));
            console.error(err);
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
                            res.status(200).json(errorFunction(false, "Your Password has been Changed Successfully"));
                        }
                        else {
                            res.status(403).json(errorFunction(true, "Incorrect Password"));
                        }
                    }
                })
            }
        }
    } catch (err) {
        console.error(err);
        res.status(400).json(errorFunction(true, "Error Changing Password"));
    }
}

async function getStats(req, res) {
    try {
        const db = getDB();
        let onlineCount = 0;
        const userAccountId = req.user['user']['account'];
        const tot_devices = await db.collection('devices').countDocuments({ account: ObjectId(userAccountId) });
        if (tot_devices == 0) {
            res.status(404).json(errorFunction(true, "User has no Registered Devices"));
        } else {
            const devices = await db.collection('devices').aggregate([
                {
                    $match: {
                        account: ObjectId(userAccountId)
                    }
                },
                {
                    $lookup: {
                        from: "pdp_ip_lease",
                        localField: "active_imsi",
                        foreignField: "imsi",
                        as: "match"
                    }
                },
                {
                    $match: {
                        match: { $ne: [] }
                    }
                },
                {
                    $count: "totalMatchedDocument"
                }
            ]).toArray();

            onlineCount = devices[0]["totalMatchedDocument"];
            res.status(200).send(errorFunction(false, "successfully fetched the Details", `total_devices: ${tot_devices},\nonline_devices: ${onlineCount},\noffline_devices: ${tot_devices - onlineCount}`))
        }
    } catch (err) {
        res.status(400).json(errorFunction(true, "Error Fetching data"))
    }
}

async function getSessionlogs(req, res) {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const page = parseInt(req.query.page) || 0;
        const db = getDB();
        let sessionId, time, imei, framedIp;
        let arr = [];
        const userAccountId = req.user['user']['account'];
        const devices = await db.collection('devices').aggregate([{
            $match: {
                account: ObjectId(userAccountId)
            }
        },
        {
            $lookup: {
                from: "pdp_ip_lease",
                localField: "active_imsi",
                foreignField: "imsi",
                as: "match"
            }
        },
        {
            $match: {
                match: { $ne: [] }
            }
        },
        {
            $skip: limit * page
        },
        {
            $limit: limit
        }]).toArray();
        devices.forEach(async device => {
            try {
                const match = device["match"][0];
                sessionId = match["session_id"]
                time = moment(match["updated_at"]).format("Do MMMM YYYY, hh:mm:ss");
                imei = match["detected_imei"];
                imsi = match["imsi"];
                framedIp = match["framed_ip_address"];
                arr.push({ sessionId, time, imei, imsi, framedIp });
            } catch (err) {
                console.error(err);
                res.status(400).json(errorFunction(true, "Error listing Devices"))
            }
        })
        // let devices1 = await db.collection('devices').aggregate([{
        //     $match: {
        //         account: ObjectId(userAccountId)
        //     }
        // },
        // {
        //     $skip : limit * page
        // },
        // {
        //     $limit: limit
        // }]).toArray();
        res.status(200).json(errorFunction(false, "successfully fetched session logs", arr));
    } catch (err) {
        console.error(err);
        res.status(400).json(errorFunction(true, "error getting session logs"))
    }
}

async function getallgroups(req, res) {
    const db = getDB();
    const userAccountId = req.user['user']['account'];
    const allGroups = await db.collection('groups').find({ account: ObjectId(userAccountId) }).toArray();
    res.status(200).json(errorFunction(false, "successfully fetched all groups", allGroups))
}

async function getgroupdetails(req, res) {
    try {
        const db = getDB();

        let groupType = parseInt(req.query.group_type);
        let arr = [];
        let groupName;
        let groups;
        let groupDesc;
        let groupActive;
        let groupDeleted;
        const userAccountId = req.user['user']['account'];
        if (groupType) {
            if (isNaN(groupType)) {
                res.status(400).json(errorFunction(true, "provide a valid group_type"));
            }
            else {
                groups = await db.collection('groups').aggregate([{
                    $match: {
                        account: ObjectId(userAccountId)
                    }
                },
                {
                    $match: {
                        group_type: groupType
                    }
                }
                ]).toArray();
            }
        }
        else {
            groups = await db.collection('groups').aggregate([{
                $match: {
                    account: ObjectId(userAccountId)
                }
            }
            ]).toArray();
        }
        groups.forEach(group => {
            try {
                groupName = group['name'];
                groupDesc = group['description'];
                groupActive = group['active'];
                groupDeleted = group['deleted'];
                groupType = group['group_type'];
                if(groupDeleted !== true){
                    arr.push({ groupName, groupDesc, groupActive, groupDeleted, groupType });
                }
            } catch (err) {
                console.error(err);
                res.status(400).json(errorFunction(true, "something went wrong please try again"));
            }
        })
        res.status(200).json(errorFunction(false, "successfully fetched group details", arr))
    } catch (err) {
        console.error(err);
        res.status(400).json(errorFunction(true, "Error getting group details"))
    }
}

module.exports = { signIn, signUp, changePassword, getAllUsers, getStats, getSessionlogs, getgroupdetails, getallgroups };