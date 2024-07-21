const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.listen(3000, () => {
    console.log('Server running on port 3000');
});

mongoose.connect('mongodb+srv://celestine:Mfonobong@cluster0.omjq230.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('Could not connect to MongoDB', err));

// User Schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String,
});

const User = mongoose.model('User', userSchema);

// Token Schema
const tokenSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  token: String,
});

const Token = mongoose.model('Token', tokenSchema);

app.post('/register', async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ firstName, lastName, email, password: hashedPassword });

    try {
      await newUser.save();
      res.status(201).send('User registered successfully');
    } catch (err) {
      res.status(400).send('Error registering user');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).send('User not found');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send('Invalid password');

    const token = jwt.sign({ id: user._id, email: user.email }, 'secretkey');
    res.status(200).json({ token });
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).send('User not found');

    const resetToken = uuidv4();
    console.log(resetToken)
    const newToken = new Token({ userId: user._id, token: resetToken });

    try {
      await newToken.save();
      // Here, send the resetToken to user's email
      res.status(200).send('Reset token sent to email');
    } catch (err) {
      res.status(400).send('Error generating reset token');
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const passwordResetToken = await Token.findOne({ token });

    if (!passwordResetToken) return res.status(400).send('Invalid or expired token');

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(passwordResetToken.userId, { password: hashedPassword });
    await Token.findByIdAndDelete(passwordResetToken._id);

    res.status(200).send('Password reset successfully');
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, 'secretkey', (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  };

  app.get('/profile', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id).select('fullName email');
    if (!user) return res.status(400).send('User not found');
    res.json(user);
});