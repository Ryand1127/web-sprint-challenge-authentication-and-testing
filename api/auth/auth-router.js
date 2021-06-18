const router = require('express').Router();
const bcrypt = require('bcryptjs')
const { JWT_SECRET } = require("../secrets")
const jwt = require('jsonwebtoken')
const Auth = require('./auth-model')
const {
  checkUsernameExists,
  validateBody,
  checkUsernameFree
} = require('./auth-middleware')

router.post('/register', checkUsernameFree, validateBody, (req, res, next) => {
  res.end('implement register, please!');
  /*
    IMPLEMENT
    You are welcome to build additional middlewares to help with the endpoint's functionality.
    DO NOT EXCEED 2^8 ROUNDS OF HASHING!

    1- In order to register a new account the client must provide `username` and `password`:
      {
        "username": "Captain Marvel", // must not exist already in the `users` table
        "password": "foobar"          // needs to be hashed before it's saved
      }

    2- On SUCCESSFUL registration,
      the response body should have `id`, `username` and `password`:
      {
        "id": 1,
        "username": "Captain Marvel",
        "password": "2a$08$jG.wIGR2S4hxuyWNcBf9MuoC4y0dNy7qC/LbmtuFBSdIhWks2LhpG"
      }

    3- On FAILED registration due to `username` or `password` missing from the request body,
      the response body should include a string exactly as follows: "username and password required".

    4- On FAILED registration due to the `username` being taken,
      the response body should include a string exactly as follows: "username taken".
  */
    const user = req.body
    const rounds = process.env.BCRYPT_ROUNDS || 8
    const hash = bcrypt.hashSync(user.password, rounds)
    user.password = hash
    Auth.insert(user)
    .then(user => {
      res.status(201).json(user)
    })
    .catch(next)
});

router.post('/login', validateBody, checkUsernameExists, (req, res) => {
  res.end('implement login, please!');
  /*
    IMPLEMENT
    You are welcome to build additional middlewares to help with the endpoint's functionality.

    1- In order to log into an existing account the client must provide `username` and `password`:
      {
        "username": "Captain Marvel",
        "password": "foobar"
      }

    2- On SUCCESSFUL login,
      the response body should have `message` and `token`:
      {
        "message": "welcome, Captain Marvel",
        "token": "eyJhbGciOiJIUzI ... ETC ... vUPjZYDSa46Nwz8"
      }

    3- On FAILED login due to `username` or `password` missing from the request body,
      the response body should include a string exactly as follows: "username and password required".

    4- On FAILED login due to `username` not existing in the db, or `password` being incorrect,
      the response body should include a string exactly as follows: "invalid credentials".
  */
  let { password } = req.body;
  const user = req.user;
  if (user && bcrypt.compareSync(password, user.password)) {
    const token = tokenBuilder(user);
    res.json({
      message: `${user.username} is back!`,
      token: token,
    });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

function tokenBuilder(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const config = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, config)
}

module.exports = router;
