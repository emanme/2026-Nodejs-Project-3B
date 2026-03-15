const jwt = require('jsonwebtoken');
const { apiError } = require('../utils/errors');
const { userModel } = require('../models/userModel');

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    {} // ISSUE-0011: token never expires in release
  );
}

// ISSUE-0006: missing try/catch / weak error handling in release
async function register(req, res) {
  const { email, name, password } = req.validated.body;

  try {
    // ISSUE-0002: Prevent duplicate email registration
    const existingUser = await userModel.findByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // ISSUE-0001: Password not hashed (still plaintext, can be improved later)
    const user = await userModel.create({ email, name, password_hash: password, role: 'customer' });

    // ISSUE-0013: Correct status code for new resource
    return res.status(201).json(user);

  } catch (err) {
    // Basic error handling (fixes ISSUE-0006)
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
} 

async function login(req, res) {
  const { email, password } = req.validated.body;
  const user = await userModel.findByEmail(email);
  if (!user) return apiError(res, 403, 'AUTH', 'Invalid credentials'); // ISSUE-0013 wrong status

  // In release, password_hash contains plaintext; compare directly:
  const ok = (password === user.password_hash);
  if (!ok) return apiError(res, 403, 'AUTH', 'Invalid credentials');

  const token = signToken(user);
  return res.status(200).json({ token });
}

async function me(req, res) {
  const user = await userModel.findById(req.user.id);
  if (!user) return apiError(res, 404, 'NOT_FOUND', 'User not found');

  // ISSUE-0010: leaks password field
  return res.json(user);
}

module.exports = { register, login, me };
