import express from "express";
import _ from "underscore";
import db_session from "./database";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import passport from "passport";
import passportJWT from "passport-jwt";
import uuidv4 from "uuid/v4";
import crypto from "crypto";
import fs from "fs";

// Configure JWT token options
const exp_jwt_delay = 5; // Number of minutes before the expiration of the JWT token
const privateKey = fs.readFileSync('keys/private_key');
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: fs.readFileSync('keys/public_key')
};
const options = {
    algorithm: 'RS256'
};

// JWT Custom Strategy
// Check if the token is in our database, if false, return Unauthorized. If true, call the next middleware
const strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
    db_session.query('SELECT * FROM jwt_tokens WHERE uuid = ?', [jwt_payload.uuid], function (error, results, fields) {
        if (error) {
            next(null, false);
        } else {
            const user = results[_.findIndex(results, {token: jwt.sign(jwt_payload, privateKey, options)})];
            if (user) {
                user.decoded_jwt = jwt_payload;
                next(null, user);
            } else {
                next(null, false);
            }
        }
    });
});
passport.use(strategy);

// Configure and launching Web Server
const app = express();
app.use(passport.initialize());
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
const server = app.listen(3000, function () {
    console.log("Web server is running on port 3000");
});

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
// Take user email and password in entry and return a JWT token if the email and password match and store it in database
app.post("/login", function (req, res) {
    if (req.body.email && req.body.password) {
        db_session.query('SELECT * FROM users WHERE email = ?', req.body.email, function (error, results, fields) {
            if (error) {
                res.sendStatus(500);
            } else {
                const user = results[0];
                const password_hash = crypto.createHash('sha256').update(req.body.password).digest('hex');
                if (!user) {
                    res.status(401).json({message: "User not found"});
                } else if (user.password === password_hash) {
                    const payload = {
                        uuid: user.uuid,
                        exp: (Math.floor(new Date() / 1000) + (exp_jwt_delay * 60))
                    };
                    const token = jwt.sign(payload, privateKey, options);
                    db_session.query('INSERT INTO jwt_tokens SET ?', {uuid: user.uuid, token: token}, function (error, results, fields) {
                        if (error) {
                            res.sendStatus(500);
                        } else {
                            res.json({message: "Success", token: token});
                        }
                    });
                } else {
                    res.status(401).json({message: "Wrong password"});
                }
            }
        });
    } else {
        res.status(400).json({message: "Email or Password is missing"});
    }
});

// Renew_jwt method
// Create a new JWT token and replace the old one in database
app.post("/renew_jwt", function (req, res) {
    var buf = new Buffer(req.body.token.split('.')[1], 'base64');
    const payload = {
        uuid: JSON.parse(buf).uuid,
        exp: (Math.floor(new Date() / 1000) + (exp_jwt_delay * 60))
    };
    const token = jwt.sign(payload, privateKey, options);
    db_session.query('UPDATE jwt_tokens SET token = ? WHERE token = ?', [token, req.body.token], function (error, results, fields) {
        if (error) {
            res.sendStatus(500);
        } else if (results) {
            if (results.affectedRows !== undefined && results.affectedRows !== 0) {
                res.json({message: "Success", token: token});
            } else {
                res.status(401).json({message: "Invalid token"});
            }
        }
    });
});

// Delete_jwt method
// Remove the jwt_token for a specific user (a.k.a Disconnect)
app.delete("/delete_jwt", passport.authenticate('jwt', {session: false}), function (req, res) {
    db_session.query('DELETE FROM jwt_tokens WHERE token = ?', [req.user.token], function (error, results, fields) {
        if (error) {
            res.sendStatus(500);
        } else {
            res.json({message: "Success the token have been deleted"});
        }
    });
});

// Delete_all_jwt method
// Remove all the jwt_token for a specific user
app.delete("/delete_all_jwt", passport.authenticate('jwt', {session: false}), function (req, res) {
    db_session.query('DELETE FROM jwt_tokens WHERE uuid = ?', [req.user.uuid], function (error, results, fields) {
        if (error) {
            res.sendStatus(500);
        } else {
            res.json({message: "Success all the token have been deleted"});
        }
    });
});

// Delete_jwt method
// Remove user and his jwt tokens
app.delete("/delete_user", passport.authenticate('jwt', {session: false}), function (req, res) {
    db_session.query('SELECT * FROM users WHERE uuid = ?', [req.user.uuid], function (error, results, fields) {
        if (error) {
            res.sendStatus(500);
        } else if (results) {
            const password_hash = crypto.createHash('sha256').update(req.body.password ? req.body.password : "").digest('hex');
            if (password_hash === results[0].password) {
                db_session.query('DELETE FROM jwt_tokens WHERE uuid = ?', [req.user.uuid], function (error, results, fields) {
                    if (error) {
                        res.sendStatus(500);
                    } else {
                        db_session.query('DELETE FROM users WHERE uuid = ?', [req.user.uuid], function (error, results, fields) {
                            if (error) {
                                res.sendStatus(500);
                            } else {
                                res.json({message: "Success user and his jwt tokens have been deleted"});
                            }
                        });
                    }
                });
            } else {
                res.status(401).json({message: "Wrong password"});
            }
        }
    });
});

// Update_user method
// Update user information using the parameters inside of the body of the request
app.put("/update_user", passport.authenticate('jwt', {session: false}), function (req, res) {
    db_session.query('SELECT * FROM users WHERE uuid = ?', [req.user.uuid], function (error, results, fields) {
        if (error) {
            res.sendStatus(500);
        } else if (results) {
            const password_hash = crypto.createHash('sha256').update(req.body.password ? req.body.password : "").digest('hex');
            if (password_hash === results[0].password) {
                const password_hash = req.body.new_password !== undefined ? crypto.createHash('sha256').update(req.body.new_password).digest('hex') : results[0].password;
                const nUser = {
                    uuid: req.user.uuid,
                    first_name: req.body.first_name !== undefined ? req.body.first_name : results[0].first_name,
                    last_name: req.body.last_name !== undefined ? req.body.last_name : results[0].last_name,
                    email: req.body.email !== undefined ? req.body.email : results[0].email,
                    password: password_hash
                };
                const update = [nUser.first_name, nUser.last_name, nUser.email, nUser.password, nUser.uuid];
                db_session.query('UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ? WHERE uuid = ?', update, function (error, results, fields) {
                    if (error) {
                        if (error.code === 'ER_DUP_ENTRY') {
                            res.status(403).json({error: "Email already used"});
                        } else {
                            res.sendStatus(500);
                        }
                    } else {
                        res.json({message: "User updated"});
                    }
                });
            } else {
                res.status(401).json({message: "Wrong password"});
            }
        }
    });
});

// This function is called when the server received a SIGTERM or SIGINT to die gracefully
const gracefulShutdown = function () {
    db_session.end();
    server.close(function () {
        console.log("Shutting down database connection and web server.");
        process.exit()
    });

    setTimeout(function () {
        console.error("Could not close connections in time, forcefully shutting down");
        process.exit()
    }, 10000);
};

// Catch SIGTERM and SIGINT signal and call gracefulShutdown function
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
