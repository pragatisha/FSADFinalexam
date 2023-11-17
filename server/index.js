const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path')

const app = express();
const PORT = process.env.PORT || 3000;

const MONGO_URI = 'mongodb+srv://st123381:jujki8-tUgruz-fegmem@cluster0.2mf7ug8.mongodb.net/';
mongoose.connect(MONGO_URI);
const db = mongoose.connection;

app.use(express.static('views'));
app.use(express.static(path.join(__dirname, '..', 'views')))


db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});


const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});


userSchema.pre('save', function (next) {
  const user = this;
  if (!user.isModified('password')) return next();

  bcrypt.genSalt(10, (err, salt) => {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});


userSchema.methods.comparePassword = function (candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    if (err) return callback(err);
    callback(null, isMatch);
  });
};

const User = mongoose.model('User', userSchema);


app.use(express.json());


app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already taken' });
    }


    const newUser = new User({ username, password });


    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {

    const user = await User.findOne({ username });


    if (!user) {
      return res.status(401).json({ message: 'Authentication failed. User not found.' });
    }


    user.comparePassword(password, (err, isMatch) => {
      if (err) throw err;

      if (isMatch) {
    
        const token = jwt.sign({ id: user._id, username: user.username }, 'secret1234', {
          expiresIn: '1h', // Token expiration time
        });

        res.cookie('token', token, { httpOnly: true });

        res.status(200).json({ token: "User login successful" });
      } else {

        res.status(401).json({ message: 'Authentication failed. Incorrect password.' });
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});