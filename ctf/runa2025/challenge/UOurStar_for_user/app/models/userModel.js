const users = new Map();

const getUser = (username) => {
    return users.get(username) ?? '';
};

const addAdminUser = () => {
    if (getUser('admin')) return;

    users.set('admin', { 
        username: 'admin', 
        password: process.env.ADMINPASS || 'fake_password',
        age: 99,
        mbti: 'CORS',
        sex: '남',
        bioRaw: '<h1>I am ADMIN</h1>', 
        themeRaw: 'color: white; background-color: black;'
    });
};

const addUser = (username, password, age, mbti, sex) => {
    if (getUser(username)) return false;

    users.set(username, {username, password, age, mbti, sex, bioRaw: '<p>안녕하세요!</p>', themeRaw: 'color: white;'});
    
    return true;
};

const updateUser = (username, { bioRaw, themeRaw }) => {
    const user = getUser(username);
    if (!user) return false;

    user.bioRaw = bioRaw;
    user.themeRaw = themeRaw;

    return true;
};

module.exports = { addUser, addAdminUser, getUser, updateUser };