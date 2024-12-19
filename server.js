const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());


mongoose.connect('mongodb://localhost:27017/userdb', { useNewUrlParser: true, useUnifiedTopology: true });


const UserSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    NIDNumber: String,
    phoneNumber: String,
    password: String,
    bloodGroup: String
});

const User = mongoose.model('User', UserSchema);


app.post('/register', async (req, res) => {
    const { firstName, lastName, NIDNumber, phoneNumber, password, bloodGroup } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, NIDNumber, phoneNumber, password: hashedPassword, bloodGroup });
    await user.save();
    res.status(201).send('User registered');
});


app.post('/login', async (req, res) => {
    const { phoneNumber, password } = req.body;
    const user = await User.findOne({ phoneNumber });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send('Invalid credentials');
    }

    const token = jwt.sign({ id: user._id }, 'your_jwt_secret');
    res.cookie('authToken', token, { httpOnly: true });
    res.status(200).send('User logged in');
});


const authenticateJWT = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) return res.sendStatus(403);

    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};


app.get('/profile', authenticateJWT, async (req, res) => {
    const user = await User.findById(req.user.id);
    res.json(user);
});

app.get('/profiles', async (req, res) => {
    const users = await User.find();
    res.json(users);
});


app.put('/profile/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    await User.findByIdAndUpdate(id, req.body);
    res.send('User profile updated');
});


app.delete('/profile/:id', async (req, res) => {
    const { id } = req.params;
    await User.findByIdAndDelete(id);
    res.send('User deleted');
});

app.listen(3000, () => console.log('Server is running on port 3000'));
