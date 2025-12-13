const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const createError = require('http-errors');
const postModel = require('./models/postModel');
const userModel = require('./models/userModel');
const app = express();
const port = 5000;

const indexRouter = require('./routes/index');
const authRouter = require('./routes/auth');
const userRouter = require('./routes/user');
const postRouter = require('./routes/post');
const adminRouter = require('./routes/admin');
const reportRouter = require('./routes/report');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/static', express.static(path.join(__dirname, 'public', 'static')));

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(session({secret: crypto.randomBytes(32).toString('hex'), resave: false, saveUninitialized: true}));
app.use((req, res, next) => {
    if (!req.session.csrfToken)
        req.session.csrfToken = crypto.randomBytes(8).toString('hex');

    res.locals.csrfToken = req.session.csrfToken;

    res.setHeader('X-Frame-Options', 'deny');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline' https: http:; img-src *`);

    next();
});

app.use('/', indexRouter);
app.use('/auth', authRouter);
app.use('/user', userRouter);
app.use('/post', postRouter);
app.use('/admin', adminRouter);
app.use('/report', reportRouter);

app.use((req, res, next) => {
    next(createError(404, ));
});

app.use((err, req, res, next) => {
    if (res.headersSent)
        return next(err);

    let status = err.status || err.statusCode || 500;

    const msgMap = {
        400: '잘못된 요청이에요.',
        401: '로그인이 필요해요.',
        403: '접근 권한이 없어요.',
        404: '페이지를 찾을 수 없어요.',
        419: 'CSRF 토큰이 유효하지 않아요.',
        500: '문제가 발생했어요. 잠시 후 다시 시도해 주세요.',
    };

    const message = msgMap[status] || err.message || msgMap[500];

    res.status(status).render('errors/errors', { status, message });
});

app.listen(port, () => {
    userModel.addAdminUser();
    postModel.seedAdminOriginalsOnce();
    console.log(`[+] Server listening on port ${port}`);
});