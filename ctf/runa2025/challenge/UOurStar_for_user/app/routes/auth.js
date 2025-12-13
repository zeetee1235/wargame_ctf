const express = require('express');
const router = express.Router();
const { addUser, getUser } = require('../models/userModel');
const { ensureSessionCopies } = require('../models/postModel');
const { loginRequired } = require('../utils');

router.get('/register', (req, res) => {
    return res.render('auth/register');
});

router.post('/register', (req, res) => {
    const { username, password, age=20, mbti='????', sex='M' } = req.body;

    if (addUser(username, password, age, mbti, sex)) {
        return res.redirect('/auth/login');
    }
    
    return res.redirect('/auth/register');
});

router.get('/login', (req, res) => {
    return res.render('auth/login');
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || getUser(username).password !== password) {
        return res.redirect('/auth/login');
    }

    req.session.username = username;
    req.session.isAdmin  = false;

    ensureSessionCopies(req.sessionID);

    return res.redirect('/');
});

router.get('/logout', loginRequired, (req, res) => {
    req.session.destroy();
    return res.redirect('/auth/login');
}); 

module.exports = router;