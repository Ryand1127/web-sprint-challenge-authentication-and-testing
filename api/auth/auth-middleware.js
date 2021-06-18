const Auth = require('./auth-model')

const validateBody = (req, res, next) => {
    const { username, password } = req.body
    if (!username.trim() || !password.trim()) {
        res.status(400).json({ message: 'username and password required' })
    } else {
        next()
    }
}

async function checkUsernameExists(req, res, next) {
    const username = req.body.username
    try{
      const  dbUsername = await Auth.findBy({username})
      if (!dbUsername) {
        res.status(401).json({ message: "Invalid credentials" })
      } else {
        next()
      }
    } catch (err) {
      next(err)
    }
  }

async function checkUsernameFree(req, res, next) {
  try {
    const username = await Auth.findBy({ username: req.body.username })
    if (!username.length) {
      next()
    } else {
      next({ "message": "Username taken", status: 422 })
    }
  } catch (err) {
    next(err)
  }
}  

module.exports = {
    validateBody,
    checkUsernameExists,
    checkUsernameFree,
}