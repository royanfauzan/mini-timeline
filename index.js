require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const { Schema } = mongoose;
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const app = express();

const port = 3000;
app.use(express.json());
app.use(cookieParser());
app.set('view engine', 'ejs');


//Koneksi Database
mongoose.connect("mongodb://127.0.0.1:27017/pb_timeline", {
    useNewUrlParser: true,
    useUnifiedTopology: true
});
const db = mongoose.connection;

db.on('error', (error) => console.log(error));
db.once('open', () => console.log("Koneksi Berhasil"));

// Models
const User = require('./models/User');
const Post = require('./models/Post');




// Route & Controller

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/data', (req, res) => {
    res.status(200).json({ message: { test: req.cookies.token } });
});

app.get('/login',mdwGuestPage, (req, res) => {
    // const usr = {id:"id123", name : "Royan Fauzan"};
    // const accessToken = jwt.sign(usr,process.env.ACCESS_TOKEN_SECRET);
    // res.cookie('token', accessToken, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true });
    res.render('login');
});

app.post('/login',
    body('password').isLength({ min: 8 }),
    body('username').not().isEmpty().trim().escape(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const usr = await User.findOne({ username: req.body.username });
        if (usr == null) {
            let erz = errors.array();
            erz.push({ msg: 'Username not Found', param: 'username' });
            return res.status(400).json({ errors: erz });
        }

        try {
            if (await bcrypt.compare(req.body.password, usr.password)) {
                const accessToken = jwt.sign({ user_id: usr._id, username: usr.username, name: usr.name }, process.env.ACCESS_TOKEN_SECRET,{expiresIn:'7d'});
                usr.token = accessToken;
                usr.save();
                res.cookie('token', accessToken, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true });
                return res.status(200).json({ message: { user_id: usr._id }, errors: errors.array() });
            } else {
                let erz = errors.array();
                erz.push({ msg: 'Credentials not Match', param: 'alert' });
                return res.status(400).json({ errors: erz });
            }
        } catch (error) {
            let erz = errors.array();
            erz.push({ msg: 'Bcrypt error', param: 'sys' });
            return res.status(400).json({ errors: erz });
        }

        // const accessToken = jwt.sign(usr, process.env.ACCESS_TOKEN_SECRET);
        // let errs = {};
        // errs.test = 'aaaa';
        // const accessToken = jwt.sign(usr,process.env.ACCESS_TOKEN_SECRET);
        // res.cookie('token', accessToken, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true });
        // res.status(401).json({ message: { email: req.body.email }, errors: errs });
        // Redirect
        // res.redirect('/');
    });

app.get('/register',mdwGuestPage, async (req, res) => {

    res.render('register');
});

app.post('/register',
    body('name').not().isEmpty().trim().escape(),
    body('password').isLength({ min: 8 }),
    body('username').custom(value => {
        return User.findOne({ username: value }).then(user => {
            if (user) {
                return Promise.reject('Username already Taken');
            }
        });
    }).not().isEmpty().trim().escape(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const hashedPassword = await bcrypt.hash(req.body.password, 10);
            const usr = { username: req.body.username, name: req.body.name, password: hashedPassword };

            User.insertMany(usr, (error, result) => {
                if (error != null) {
                    console.log(error)
                } else {
                    res.status(200).json({ message: { email: req.body.email }, errors: errors });
                }
            })
            // const accessToken = jwt.sign(usr, process.env.ACCESS_TOKEN_SECRET);
            // errs.test = 'aaaa';
            // const accessToken = jwt.sign(usr,process.env.ACCESS_TOKEN_SECRET);
            // res.cookie('token', accessToken, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true });
            // res.status(200).json({ message: { email: req.body.email }, errors: errors });
        } catch (error) {
            res.status(400).json({ errors: errors.array() });
        }
    });

async function mdwLoggedinApi(req, res, next) {
    const currUsr = await authenticateToken(req)
    if (!currUsr) {
        return res.status(403).json({ errors: [{ errorCode: 403, action: 'redirect', redirectTo: '/login' }] });
    }
    req.currUser = currUsr;
    next();
}

async function mdwGuestApi(req, res, next) {
    const currUsr = await authenticateToken(req)
    if (currUsr) {
        return res.status(403).json({ errors: [{ errorCode: 403, action: 'redirect', redirectTo: '/login' }] });
    }
    next();
}

async function mdwGuestPage(req, res, next) {
    const currUsr = await authenticateToken(req);
    console.log(currUsr);
    if (currUsr) {
        return res.redirect('/home');
    }else{
        next();
    }
    
}

async function authenticateToken(req) {
    const usrToken = req.cookies.token;
    let usr = await User.findOne({ token: usrToken })
    if (usr == null) {
        return false;
    }

    const decode = jwt.verify(usrToken, process.env.ACCESS_TOKEN_SECRET)
    return decode;
    // return usr;
}


app.get('*', (req, res) => {
    res.render('404');
});

app.listen(port, () => {
    console.log(`Listening to http://localhost:${port}`);
});
