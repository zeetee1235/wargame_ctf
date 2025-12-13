const express = require('express')
const router = express.Router();
const { visit } = require('../bot.js');
const { getUser } = require('../models/userModel');
const { loginRequired, validateCSRFToken } = require('../utils.js');

router.get('/', loginRequired, (req, res, next) => {
    return res.render('report/report', { userinfo: getUser(req.session.username), message: null });
});

router.post('/', loginRequired, validateCSRFToken, async (req, res, next) => {
    const username = req.body.username;
    const reporterId = req.sessionID;
    const ok = await visit({ reporterId, username });

    return res.render('report/report', {
        userinfo: getUser(req.session.username),
        message: ok ? '접수됐어요.' : '문제가 발생했어요.'
    });
});

module.exports = router;