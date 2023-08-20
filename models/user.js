const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  verificationCode: { type: String },
});

// Hash the password before saving the user
userSchema.pre('save', async function (next) {
  const user = this;

  if (!user.isModified('password')) return next();
  
  // Check if the email field is null or empty before saving
  if (user.email === null || user.email.trim() === "") {
    const err = new Error('Email cannot be null or empty.');
    return next(err);
  }
  // console.log('Password to be hashed:', user.password);

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(user.password, salt);
    user.password = hashedPassword;
    next();
  } catch (error) {
    console.error('Error during password hashing:', error);
    return next(error);
  }

  // user.password = user.password;

  // next();
});

// Method to compare password during login
userSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    // console.log('Candidate password:', candidatePassword);
    // console.log('Stored hashed password:', this.password);

    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    // console.log("Password Match:", isMatch);

    return isMatch;
  } catch (error) {
    throw error;
  }
};

const User = mongoose.model('User', userSchema);
module.exports = User;
