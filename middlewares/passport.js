const { ObjectId } = require('mongodb');
const passport = require('passport');
const { getDB } = require('../config/db');
require('dotenv').config();


const  JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt;

const opts = {}
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.JWT_SECRET;
passport.use(new JwtStrategy(opts, async function(jwt_payload, done) {
    const db = getDB();
    const userAccountId = jwt_payload.user._id;
    const user = await db.collection('users').find({_id : ObjectId(userAccountId)}).toArray();
    if(user){
        return done(null, user)
    }else {
        return done(null, false);
    }
}));