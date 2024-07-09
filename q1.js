const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();


let users = [
    {
        id: 1,
        username: 'User1',
        passwordHash: '$2a$10$kgvQK4DQZ8G6H2.Y6LJGM.YrS5IUUC9ujzKqyMGuR6OhGPhW43dfy',
    }
];


const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, 'secret', (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }

            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};
router.post('/update-password', authenticateJWT, (req, res) => {
    const { userId, newPassword } = req.body;

   
    const user = users.find(u => u.id === userId);

    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    
    bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).json({ message: 'Error hashing password' });
        }

        user.passwordHash = hashedPassword;

        res.status(204).end(); 
    });
});

module.exports = router;
