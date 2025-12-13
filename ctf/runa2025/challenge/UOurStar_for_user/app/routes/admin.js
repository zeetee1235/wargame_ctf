const express = require('express');
const router = express.Router();
const { loginRequired, validateCSRFToken, adminOnly } = require('../utils');
const { setVisible } = require('../models/postModel');

// TODO: implement blind feature.. but I'll do it later!
router.post('/blind', adminOnly, validateCSRFToken, (req, res, next) => {
    return res.status(200).send('Under Construction...');
});

router.post('/setVisible', adminOnly, validateCSRFToken, (req, res, next) => {
    const result = setVisible(req.body.postId);
    return res.status(200).send(result);
});

module.exports = router;