const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const bcrypt = require('bcrypt');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

// Connect to your MongoDB database
mongoose.connect('mongodb+srv://Cluster60627:Michelle33@cluster60627.wuhbtvh.mongodb.net/?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Create a new MongoDB session store
const store = new MongoDBStore({
  uri: 'mongodb+srv://Cluster60627:Michelle33@cluster60627.wuhbtvh.mongodb.net/?retryWrites=true&w=majority',
  collection: 'sessions',
});

// Handle session and cookie settings
app.use(
  session({
    secret: '7EdLMwAD5cPGIM6zuNwSKfbk5mjaOQBpn98seMZjWsEBc2ALAH9zk5Uq8HqhD6NC',
    resave: false,
    saveUninitialized: false,
    store: store,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 90, // Session will expire after 90 days
      httpOnly: true,
      secure: false, // Set to true for HTTPS
    },
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('views'));

// Define the User model
const User = require('./models/user');

// Function to send the verification email
async function sendVerificationEmail(email, verificationCode) {
  try {
    const transporter = nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 587,
      secure: false,
      auth: {
        user: 'apikey',
        pass: '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',
      },
    });

    await transporter.sendMail({
      from: 'mcastro32902@gmail.com',
      to: 'mcastro32902@gmail.com',
      subject: 'Account Verification',
      text: `The email trying to register is ${email}. \nThe verification code is: ${verificationCode}`,
    });

    console.log('Verification email sent successfully.');
  } catch (error) {
    console.error('Error sending verification email:', error);
    throw new Error('Failed to send verification email.');
  }
}

function generateVerificationCode() {
  const code = crypto.randomBytes(3).toString('hex').toUpperCase();
  return code;
}

// Home route - Redirect to login page
app.get('/', (req, res) => {
  res.redirect('/login');
});

// Login route
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // console.log('Input Password:', password);

  try {
    // console.log("Email:", email);
    // console.log("Password:", password);

    const user = await User.findOne({ email: email });
    // console.log("User:", user);

    if (!user) {
      console.log("User not found");
      return res.redirect('/login?error=Invalid%20email%20or%20password.');
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);

    // console.log("isPasswordValid:", isPasswordValid);

    if (!isPasswordValid) {
      console.log("Invalid password");
      return res.redirect('/login?error=Invalid%20email%20or%20password.');
    }

    if (!user.isVerified) {
      console.log("Email not verified");
      return res.redirect('/login?error=Email%20not%20verified.');
    }

    req.session.userId = user._id;
    console.log("Login successful");
    res.redirect('/content');
  } catch (error) {
    console.error('Error occurred during login:', error);
    res.send('Error occurred during login.');
  }
});

// Register route
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

const uppercaseRegex = /[A-Z]/;
const specialCharacterRegex = /[^A-Za-z0-9]/g;
const numberRegex = /\d/g;

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // console.log("Email:", email);
  // console.log("Password:", password);

  // Check if the email is valid and not null or empty
  if (!email || email.trim() === "") {
    console.log("Invalid email");
    return res.redirect('/register?error=Please%20provide%20a%20valid%20email%20address.');
  }

  // Check if the password meets the requirements
  if (
    !uppercaseRegex.test(password) ||
    (password.match(specialCharacterRegex) || []).length < 1 ||
    (password.match(numberRegex) || []).length < 1
  ) {
    console.log("Invalid password format");
    return res.redirect('/register?error=Password%20must%20contain%20at%20least%20one%20uppercase%20letter,%20more%20than%20one%20special%20character,%20and%20more%20than%20one%20number.');
  }
  try {
    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
      console.log("Email is already taken");
      return res.redirect('/register?error=Email%20is%20already%20taken.');
    }

    const verificationCode = generateVerificationCode();
    await sendVerificationEmail(email, verificationCode);

    // const hashedPassword = await bcrypt.hash(password, 10);
    // console.log('Password', password);
    // console.log('Hashed Password', hashedPassword);
    const newUser = new User({
      email,
      password,
      verificationCode,
    });

    await newUser.save();

    return res.redirect('/login?success=Email%20will%20be%20checked.');
  } catch (error) {
    console.error('Error occurred during registration:', error);
    res.send('Error occurred during registration.');
  }
});

// Verify route - Handle the user's verification code
app.get('/verify', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'verify.html'));
});

app.post('/verify', async (req, res) => {
  const { email, verificationCode } = req.body;
  // console.log("Email:", email);
  // console.log("Verification code:", verificationCode);

  try {
    const user = await User.findOne({ email });

    // console.log("User:", user);

    if (!user) {
      console.log("User not found");
      return res.send('User not found.');
    }

    if (user.verificationCode === verificationCode) {
      console.log("Verification successful");
      user.isVerified = true;
      await user.save();
      return res.redirect('/login?success=Account%20verified%20successfully!');
    } else {
      console.log("Invalid verification code");
      return res.redirect('/login?error=Invalid%20verification%20code.%20Please%20try%20again.');
    }
  } catch (error) {
    console.error('Error occurred during verification:', error);
    res.send('Error occurred during verification.');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.send('Error occurred during logout.');
    }
    res.redirect('/login');
  });
});

// Content route
app.get('/content', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }

  res.sendFile(path.join(__dirname, 'views', 'content.html'));
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
