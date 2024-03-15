const User = require('../model/User');
const Blog = require('../model/Blog');
const Token = require('../model/Token');
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const crypto = require("crypto");
const SendEmail = require("../utils/util");
const dotenv = require('dotenv').config();
const { otpGenerator } = require('../utils/otpgenerator');

module.exports.Login = async (req, res) => {
    const { Username, Password } = req.body;
    try {
        const user = await User.findOne({ Username });
        if (!user) {
            return res.send("User not found");
        }
        if (!user.is_verify) {
            return res.send("User not verified");
        }
        const match = await bcrypt.compare(Password, user.Password);
        if (match) {
            req.session.user = user;
            req.session.isLoggedIn = true;
            if (user.Admin) {
                return res.redirect('/admin');
            } else {
                return res.redirect('/');
            }
        } else {
            return res.send("Invalid Password");
        }
    } catch (error) {
        console.error(error);
        return res.status(500).send("Internal Server Error");
    }
}

module.exports.LoginPage = (req, res) => {
    if (req.session.isLoggedIn) {
        return res.redirect('/profile');
    } else {
        return res.render('login.hbs');
    }
}

module.exports.RegisterPage = (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.render('register.hbs');
    } else {
        return res.redirect('/admin');
    }
}

module.exports.Register = async (req, res) => {
    const { Username, Password } = req.body;
    try {
        const checkUser = await User.findOne({ Username });
        if (checkUser) {
            return res.send("User already registered");
        }
        if (!Username || !Password) {
            return res.status(400).send("Username and Password are required");
        }
        bcrypt.hash(Password, saltRounds, async (err, hash) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Internal Server Error");
            }
            const newUser = new User({ Username, Password: hash });
            await newUser.save();
            const otp = otpGenerator();
            const token = await new Token({
                userId: newUser._id,
                token: crypto.randomBytes(32).toString("hex"),
                otp: otp
            }).save();
            const message = `Verify your account using this otp : ${otp}\n${process.env.BASE_URL}user/verify/${newUser.id}/${token.token}`;
            await SendEmail.SendEmail(newUser.Username, "Verify Email", message);
            return res.send("Verify your email by clicking link sent to your email");
        });
    } catch (error) {
        console.error(error);
        return res.status(500).send("Internal Server Error");
    }
}

module.exports.AdminPage = async (req, res) => {
    try {
        if (req.session.isLoggedIn && req.session.user.Admin) {
            const blogs = await Blog.find({});
            return res.render('adminpages/index.hbs', { blogs, user: req.session.user });
        } else {
            return res.redirect('/');
        }
    } catch (error) {
        console.error(error);
        return res.status(500).send("Internal Server Error");
    }
}

module.exports.Logout = (req, res) => {
    req.session.isLoggedIn = false;
    req.session.user = null;
    return res.redirect('/');
}

module.exports.CategoryPage = (req, res) => {
    if (req.session.isLoggedIn) {
        return res.render('category.hbs', { user: req.session.user });
    } else {
        return res.render('category.hbs');
    }
}

module.exports.Category = async (req, res) => {
    const { category } = req.body;
    try {
        let blogs;
        if (req.session.isLoggedIn) {
            blogs = await Blog.find({ category, is_verified: true });
            return res.render('category.hbs', { blogs, user: req.session.user });
        } else {
            blogs = await Blog.find({ category, is_verified: true });
            return res.render('category.hbs', { blogs, category });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).send("Internal Server Error");
    }
}

module.exports.ProfilePage = async (req, res) => {
    try {
        if (req.session.isLoggedIn) {
            const userblogs = await Blog.find({ user_id: req.session.user._id });
            return res.render('profile', { user: req.session.user, blogs: userblogs });
        } else {
            return res.redirect('/');
        }
    } catch (error) {
        console.error(error);
        return res.status(500).send("Internal Server Error");
    }
}

module.exports.Admin = async (req, res) => {
    const { id } = req.params;
    const { is_verify } = req.query;
    try {
        await Blog.findByIdAndUpdate(id, { is_verified: is_verify });
        return res.send("Blog verification status updated");
    } catch (error) {
        console.error(error);
        return res.status(500).send("Internal Server Error");
    }
}
