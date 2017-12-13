import express from "express";
import _ from "underscore";
import db_session from "./database";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import passport from "passport";
import passportJWT from "passport-jwt";
import uuidv4 from "uuid/v4";
import crypto from "crypto";

const expiration_jwt_delay = 5; // Number of minutes before the expiration of the JWT token

const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
jwtOptions.secretOrKey = 'superSecret'; // TODO: Move from secret to Key ?


// Check if the token is still valid or not
const strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
    if (jwt_payload.expiration > Math.floor(new Date() / 1000)) {
        // TODO: Maybe remove this check because of redundancy ?
        db_session.query('SELECT * FROM users', function (error, results, fields) {
            if (error) {
                next(null, false);
            } else {
                const user = results[_.findIndex(results, {uuid: jwt_payload.uuid})];
                if (user) {
                    next(null, user);
                } else {
                    next(null, false);
                }
            }
        });
    } else {
        next(null, false);
    }
});

passport.use(strategy);

const app = express();
app.listen(3000);
app.use(passport.initialize());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

// Register method
// Take first_name, last_name, email and password in entry.
// Check if user is not already registered, if not, generate a UUID and then create a new record in database
app.post('/register', (req, res) => {
    if (req.body.first_name && req.body.last_name && req.body.email && req.body.password) {
        const password_hash = crypto.createHash('sha256').update(req.body.password).digest('hex');
        const user_info = {
            uuid: uuidv4(),
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            email: req.body.email,
            password: password_hash
        };
        db_session.query('SELECT * FROM users WHERE email = ?', [req.body.email], function (error, results, fields) {
            if (error) {
                res.sendStatus(500);
            } else {
                if (results.length !== 0) {
                    res.status(403).json({message: "User is already registered"});
                } else {
                    db_session.query('INSERT INTO users SET ?', user_info, function (error, results, fields) {
                        if (error) {
                            res.sendStatus(500);
                        } else {
                            res.json({message: "User successfully created"});

                        }
                    });
                }
            }
        });
    } else {
        res.status(400).json({message: "Something is missing, please verify your POST parameters"});
    }
});

// Login method
// Take user email and password in entry and return a JWT token if the email and password match
app.post("/login", function (req, res) {
    if (req.body.email && req.body.password) {
        db_session.query('SELECT * FROM users', function (error, results, fields) {
            if (error) {
                res.sendStatus(500);
            } else {
                const user = results[_.findIndex(results, {email: req.body.email})];
                const password_hash = crypto.createHash('sha256').update(req.body.password).digest('hex');
                if (!user) {
                    res.status(401).json({message: "User not found"});
                } else if (user.password === password_hash) {
                    const payload = {uuid: user.uuid, expiration: (Math.floor(new Date() / 1000) + (expiration_jwt_delay * 60))};
                    const token = jwt.sign(payload, jwtOptions.secretOrKey);
                    res.json({message: "Success", token: token});
                } else {
                    res.status(401).json({message: "Wrong password"});
                }
            }
        });
    } else {
        res.status(401).json({message: "No data received"});
    }
});


// Renew_jwt method
// Create a new JWT token
app.get("/renew_jwt", passport.authenticate('jwt', {session: false}), function (req, res) {
    const payload = {uuid: req.user.uuid, expiration: (Math.floor(new Date() / 1000) + (expiration_jwt_delay * 60))};
    const token = jwt.sign(payload, jwtOptions.secretOrKey);
    res.json({message: "Success", token: token});
});

// TODO: Graceful shutdown (express + db)