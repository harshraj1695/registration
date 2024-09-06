// server/server.js

const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('./db');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// Register route
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password, email) VALUES ($1, $2, $3)',
            [username, hashedPassword, email]
        );
        // Redirect to login page after successful registration
        res.send('<script>alert("Registration successful! Please log in."); window.location.href="/";</script>');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error registering user');
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(400).send('User not found');
        }

        const user = result.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).send('Invalid password');
        }

        // On successful authentication, redirect to YouTube
        res.send('<script>window.location.href="https://www.youtube.com";</script>');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error during authentication');
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
