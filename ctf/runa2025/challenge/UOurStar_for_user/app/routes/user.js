const express = require('express');
const router = express.Router();
const createError = require('http-errors');
const { getUser, updateUser } = require('../models/userModel');
const { loginRequired, validateCSRFToken } = require('../utils.js');
const { getPostsByAuthor } = require('../models/postModel.js');

// view profile
router.get('/profile/:username', loginRequired, (req, res, next) => {
    const userinfo = getUser(req.params.username);
    const isOwner = req.session.username === req.params.username;
    const isAdmin = req.session.username === 'admin';
    if (!userinfo) return next(createError(404, ));

    return res.render('user/profile', { userinfo, isOwner, isAdmin });
});

// edit profile bio & theme
// TODO: add username, mbti, sex edit feature.. but I'll do it later!
router.post('/profile/:username', loginRequired, validateCSRFToken, (req, res) => {
    if (req.session.username !== req.params.username) {
        return next(createError(403, ));
    }

    const { bio = '', theme = '' } = req.body;

    updateUser(req.params.username, { bioRaw: bio, themeRaw: theme });

    return res.redirect(`/user/profile/${req.params.username}`);
});

module.exports = router;