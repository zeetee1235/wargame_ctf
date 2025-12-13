const { v4: uuidv4 } = require('uuid');
const posts = new Map();
const clonedSessions = new Set();
const FLAG = process.env.FLAG || 'runa2025{**fake_flag**}';

const seedAdminOriginalsOnce = (() => {
    if ([...posts.values()].some(p => p.sessionId === '__ORIGINAL__')) return;
    addPost('admin', {
        sessionId: '__ORIGINAL__',
        title: 'Look at me!',
        content: FLAG,
        isPrivate: true,
    });
    console.log(posts);
});

const ensureSessionCopies = ((sessionId) => {
    if (!sessionId || clonedSessions.has(sessionId)) return;

    const [original] = [...posts.values()].filter(p => p.sessionId === '__ORIGINAL__');

    addPost(original.author, {
        sessionId: sessionId,
        title: original.title,
        content: original.content,
        isPrivate: original.isPrivate,
    });

    clonedSessions.add(sessionId);
});

const listBySession = ((sessionId) => {
    return [...posts.values()].filter(p => p.sessionId === sessionId);
});

const getPostById = (postId) => {
    return posts.get(postId) ?? null;
}

const addPost = (author, body) => {
    const postId = uuidv4();
    const post = { 
        postId: postId,
        sessionId: body.sessionId, 
        author: author, 
        title: body.title, 
        content: body.content,
        isPrivate: body.isPrivate
    };

    posts.set(postId, post);

    return postId;
};

const editPost = (postId, body) => {
    const post = getPostById(postId);
    if (!post) return false;

    post.title = body.title;
    post.content = body.content;
    post.isPrivate = body.isPrivate;

    return true;
};

const deletePost = (postId) => {
    const post = getPostById(postId);
    if (!post) 
        return false;

    posts.delete(postId);

    return true;
}

const setVisible = (postId) => {
    const post = getPostById(postId);
    if (!post) 
        return false;

    post.isPrivate = false;
    console.log(post);

    return true;
};

module.exports = { 
    seedAdminOriginalsOnce, 
    ensureSessionCopies, 
    listBySession, 
    getPostById, 
    addPost, 
    editPost, 
    deletePost,
    setVisible 
};