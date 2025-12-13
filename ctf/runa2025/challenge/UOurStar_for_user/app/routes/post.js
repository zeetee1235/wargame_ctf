const express = require('express');
const router = express.Router();
const createError = require('http-errors');
const { getPostById, addPost, deletePost, editPost } = require('../models/postModel');
const { loginRequired, validateCSRFToken, validateAuthor } = require('../utils.js');
const { getUser } = require('../models/userModel');

// write post
router.get('/write', loginRequired, (req, res, next) => {
    const username = req.session.username;
    return res.render('post/write', { userinfo: getUser(username), author: username });
});

router.post('/write', loginRequired, validateCSRFToken, (req, res, next) => {
    const sessionId = req.sessionID;
    const title = (req.body.title || '제목 없음').trim();
    const content = (req.body.content || '할 말이 없으신가요?').trim();
    const isPrivate = req.body.isPrivate === 'true';
    const author = req.session.username;
    const body = { sessionId, title, content, isPrivate };

    const postId = addPost(author, body);

    return res.redirect(`/post/${postId}`);
});

router.get('/edit/:postId', loginRequired, validateAuthor, (req, res, next) => {
    const post = getPostById(req.params.postId);

    if (!post) return next(createError(404, ));

    return res.render('post/write', { userinfo: getUser(req.session.username), post: post });
});

router.post('/edit/:postId', loginRequired, validateCSRFToken, validateAuthor, (req, res, next) => {
    const title = (req.body.title || '제목 없음').trim();
    const content = (req.body.content || '할 말이 없으신가요?').trim();
    const isPrivate = req.body.isPrivate === 'true';
    const body = { title, content, isPrivate };

    if(editPost(req.params.postId, body))
        return res.redirect(`/post/${req.params.postId}`);

    return next(createError(500, ));
});

router.post('/delete/:postId', loginRequired, validateCSRFToken, validateAuthor, (req, res, next) => {
    if (deletePost(req.params.postId))
        return res.redirect('/');

    return next(createError(404, ));
});

// view post
router.get('/:postId', loginRequired, (req, res, next) => {
    const post = getPostById(req.params.postId);

    if (!post) 
        return next(createError(404, ));
    if (post.isPrivate) 
        return next(createError(403, ));

    return res.render('post/view', { userinfo: getUser(req.session.username), post: post });
});

module.exports = router;