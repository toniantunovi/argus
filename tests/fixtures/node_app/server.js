const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.json());

// Command injection: user input in exec
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// XSS: unescaped user input
app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${name}!</h1>`);
});

// SQL injection via string concatenation
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    // db.query(query, ...)
    res.json({ query });
});

// Missing auth on admin route
app.delete('/admin/users/:id', (req, res) => {
    const userId = req.params.id;
    // No auth check
    // db.deleteUser(userId);
    res.json({ deleted: userId });
});

function hashPassword(password) {
    const crypto = require('crypto');
    // Weak: MD5 for password hashing
    return crypto.createHash('md5').update(password).digest('hex');
}

module.exports = app;
