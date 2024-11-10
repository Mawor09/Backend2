const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const User = require('../models/User');

const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['token'];
    }
    return token;
};

const opts = {
    jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]),
    secretOrKey: process.env.JWT_SECRET // Definir la clave secreta en .env
};

passport.use('jwt', new JwtStrategy(opts, (jwt_payload, done) => {
    User.findById(jwt_payload.id)
        .then(user => {
            if (user) return done(null, user);
            return done(null, false);
        })
        .catch(err => done(err, false));
}));

module.exports = passport;
