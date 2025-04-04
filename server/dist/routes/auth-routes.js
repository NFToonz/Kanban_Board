import { Router } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
export const login = async (req, res) => {
    // TODO: If the user exists and the password is correct, return a JWT token
    const { username, password } = req.body; // Get the username and password from the request body
    // Find the user in the database
    const user = await User.findOne({
        where: { username, },
    });
    // If the user is not found, return a 404 status
    if (!user) {
        return res.sendStatus(404).json({ message: 'User not found' });
    }
    // If the password is incorrect, return a 401 status
    if (!await bcrypt.compare(password, user.password)) {
        return res.sendStatus(401).json({ message: 'Incorrect password' });
    }
    // Create a JWT token
    const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET);
    return res.json({ accessToken }); // Return the token to the user
};
const router = Router();
// POST /login - Login a user
router.post('/login', login);
export default router;
