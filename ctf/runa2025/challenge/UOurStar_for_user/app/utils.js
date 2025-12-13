const createError = require('http-errors');
const { getPostById } = require('./models/postModel');

const loginRequired = (req, res, next) => {
    if (req.session && req.session.username) return next();
    return res.redirect('/auth/login');
};

const validateCSRFToken = (req, res, next) => {
    if (!req.session || !req.session.csrfToken) 
        return res.redirect('/auth/login');

    const csrfToken = req.body._csrf;
    if (csrfToken !== req.session.csrfToken) 
        return next(createError(419, ));

    return next();
};

const adminOnly = (req, res, next) => {
    if (req.session.username !== "admin") 
        return next(createError(403, ));

    return next();
};

const validateAuthor = (req, res, next) => {
    const post = getPostById(req.params.postId);
    if (!post) 
        return next(createError(404, ));
    
    if (req.session.username !== post.author)
        return next(createError(403, ));
        
    return next();
};

module.exports = { loginRequired, validateCSRFToken, adminOnly, validateAuthor };