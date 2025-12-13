const express = require('express');
const router = express.Router();
const { listBySession } = require('../models/postModel');
const { getUser } = require('../models/userModel');
const { loginRequired } = require('../utils');

router.get('/', loginRequired, (req, res) => {
    return res.render('index/index', { userinfo: getUser(req.session.username), posts: listBySession(req.sessionID) });
});

module.exports = router;