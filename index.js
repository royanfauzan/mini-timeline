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

app.get('/login', mdwGuestPage, (req, res) => {
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
                const accessToken = jwt.sign({ user_id: usr._id, username: usr.username, name: usr.name }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '7d' });
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

    });

app.get('/register', mdwGuestPage, async (req, res) => {

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

        } catch (error) {
            res.status(400).json({ errors: errors.array() });
        }
    });

app.get('/home', mdwLoggedinPage, async (req, res) => {
    const listPosts = await Post.find().populate('owner', 'name username').populate('likes', 'name username')
    res.render('home', {
        listPosts: listPosts,
        user_id: req.currUser.user_id
    });
});

app.get('/post/create', mdwLoggedinPage,
    async (req, res) => {
        res.render('createpost');
    });

app.post('/post/create', mdwLoggedinApi,
    body('textpost').not().isEmpty().trim().escape(),
    async (req, res) => {

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            // const hashedPassword = await bcrypt.hash(req.body.password, 10);
            const post = { owner: req.currUser.user_id, text: req.body.textpost, likes: [] };

            Post.insertMany(post, (error, result) => {
                if (error != null) {
                    let erz = errors.array();
                    erz.push({ msg: error, param: 'alert' });
                    console.log(error)
                    return res.status(400).json({ errors: erz });
                } else {
                    res.status(200).json({ message: { email: req.body.textpost }, errors: errors });
                }
            })

        } catch (error) {
            let erz = errors.array();
            erz.push({ msg: error, param: 'alert' });
            return res.status(400).json({ errors: erz });
        }
    });

app.get('/post/edit/:id', mdwLoggedinPage,
    async (req, res) => {
        const post = await Post.findById(req.params.id).populate('owner', 'name username').populate('likes', 'name username')
        res.render('editpost', {
            post: post
        });
    });

app.post('/post/edit/:id', mdwLoggedinApi,
    body('textpost').not().isEmpty().trim().escape(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const post = await Post.findById(req.params.id)

        if (post == null) {
            let erz = errors.array();
            erz.push({ msg: 'Post Not Found', param: 'alert' });
            return res.status(400).json({ errors: erz });
        }

        try {
            if (req.currUser.user_id == post.owner) {
                post.text = req.body.textpost
                post.save()
                return res.status(200).json({ message: { email: req.body.textpost }, errors: errors });
            } else {
                let erz = errors.array();
                erz.push({ msg: `${req.currUser.user_id} owner : ${post.owner}`, param: 'alert' });
                return res.status(400).json({ errors: erz });
            }
        } catch (error) {
            let erz = errors.array();
            erz.push({ msg: `${error} `, param: 'alert' });
            return res.status(400).json({ errors: erz });
        }
    });

app.post('/post/addlikes/:id', mdwLoggedinApi,
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const post = await Post.findById(req.params.id)

        if (post == null) {
            let erz = errors.array();
            erz.push({ msg: 'Post Not Found', param: 'alert' });
            return res.status(400).json({ errors: erz });
        }

        try {
            post.likes.push(req.currUser.user_id);
            post.save();
            return res.status(200).json({ message: { email: req.body.textpost }, errors: errors });
            
        } catch (error) {
            let erz = errors.array();
            erz.push({ msg: `${error} `, param: 'alert' });
            return res.status(400).json({ errors: erz });
        }
    });

    app.post('/post/removelikes/:id', mdwLoggedinApi,
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const post = await Post.findById(req.params.id)

        if (post == null) {
            let erz = errors.array();
            erz.push({ msg: 'Post Not Found', param: 'alert' });
            return res.status(400).json({ errors: erz });
        }

        try {
            post.likes.pull(req.currUser.user_id);
            post.save();
            return res.status(200).json({ message: { email: req.body.textpost }, errors: errors });
            
        } catch (error) {
            let erz = errors.array();
            erz.push({ msg: `${error} `, param: 'alert' });
            return res.status(400).json({ errors: erz });
        }
    });

app.delete('/post/delete/:id', mdwLoggedinApi,
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const post = await Post.findById(req.params.id)

        if (post == null) {
            let erz = errors.array();
            erz.push({ msg: 'Post Not Found', param: 'alert' });
            return res.status(400).json({ errors: erz });
        }

        try {
            if (req.currUser.user_id == post.owner) {
                Post.findByIdAndDelete(req.params.id, (err, post) => {
                    return res.status(200).json({ message: { delete: post }, errors: err });
                })

            } else {
                let erz = errors.array();
                erz.push({ msg: `${req.currUser.user_id} owner : ${post.owner}`, param: 'alert' });
                return res.status(400).json({ errors: erz });
            }
        } catch (error) {
            let erz = errors.array();
            erz.push({ msg: `${error} `, param: 'alert' });
            return res.status(400).json({ errors: erz });
        }
    });

// middlewares

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
    } else {
        next();
    }

}

async function mdwLoggedinPage(req, res, next) {
    const currUsr = await authenticateToken(req);
    console.log(currUsr);
    if (!currUsr) {
        return res.redirect('/login');
    } else {
        req.currUser = currUsr;
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
