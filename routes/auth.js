// routes/auth.js
const express = require('express');
const router = express.Router();
const db = require('../db');
const { body, validationResult } = require("express-validator");
var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");

// Middleware to validate user input
// const validateUserInput = (req, res, next) => {
//     const { name, email, password } = req.body;
    
//     if (!name || !email || !password) {
//         return res.status(400).json({
//             status: 'error',
//             message: 'All fields are required'
//         });
//     }

//     // Basic email validation
//     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//     if (!emailRegex.test(email)) {
//         return res.status(400).json({
//             status: 'error',
//             message: 'Invalid email format'
//         });
//     }

//     // Basic password validation (minimum 6 characters)
//     if (password.length < 6) {
//         return res.status(400).json({
//             status: 'error',
//             message: 'Password must be at least 6 characters long'
//         });
//     }

//     next();
// };

// Register new user
router.post('/signup', [
  body("name", "enter the valid name").isLength({ min: 3 }),
  body("email", "enter the valid email").isEmail(),
  body("password", "enter the valid password").isLength({ min: 6 }),
], async(req, res) => {
  const result = validationResult(req);
  if (!result.isEmpty()) {
    success = false;
    return res.json({ success, errors: result.array() });
  }
  const { name, email, password } = req.body;
  // Check if user already exists
  const checkUser = 'SELECT email FROM users WHERE email = ?';
  db.query(checkUser, [email], (error, results) => {
      if (error) {
          return res.status(500).json({
              status: 'error',
              message: 'Database error',
              error: error
          });
      }
      if (results.length > 0) {
          return res.status(400).json({
              status: 'error',
              message: 'Email already registered'
          });
      }
    });
    const salt = await bcrypt.genSaltSync(10);
    const secPass = await bcrypt.hash(req.body.password, salt);
    // Insert new user
    const insertUser = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    db.query(insertUser, [name, email, secPass], (error, results) => {
        if (error) {
            return res.status(500).json({
                status: 'error',
                message: 'Error registering user',
                error: error
            });
        }
        res.status(201).json({
            status: 'success',
            message: 'User registered successfully',
            userId: results.insertId
        });
    });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if user exists
  const checkUser = 'SELECT name, email, password FROM users WHERE email = ?';
  db.query(checkUser, [email], async (error, results) => {
      if (error) {
          return res.status(500).json({
              status: 'error',
              message: 'Database error',
              error: error
          });
      }

      if (results.length === 0) {
          return res.status(400).json({
              status: 'error',
              message: 'Invalid email or password'
          });
      }

      const user = results[0];
      try {
          // Compare the provided password with the hashed password in the database
          const isMatch = await bcrypt.compare(password, user.password);

          if (!isMatch) {
              return res.status(400).json({
                  status: 'error',
                  message: 'Invalid email or password'
              });
          }

          // Create JWT token
          const data = { email: user.email, name: user.name }; // Adjust the payload as needed
          const token = jwt.sign(data, "shhhhh", { expiresIn: '1h' });

          res.status(200).json({
              status: 'success',
              message: 'User logged in successfully',
              user: { name: user.name, email: user.email },
              token: token
          });
      } catch (error) {
          return res.status(500).json({
              status: 'error',
              message: 'Error comparing passwords',
              error: error.message
          });
      }
  });
});

router.get('/users', (req, res) => {
  const query = 'SELECT * FROM users';  // Note: excluding password for security
  
  db.query(query, (error, results) => {
      if (error) {
          return res.status(500).json({
              status: 'error',
              message: 'Error fetching users',
              error: error
          });
      }

      // If no users found
      if (results.length === 0) {
          return res.status(200).json({
              status: 'success',
              message: 'No users found',
              data: []
          });
      }

      // Return users
      res.status(200).json({
          status: 'success',
          message: 'Users retrieved successfully',
          data: results
      });
  });
});



router.put('/updateuser/:id', (req, res) => {
  const id = req.params.id;
  const { name, email } = req.body;
  const query = 'UPDATE users SET name = ?, email = ? WHERE id = ?';
  
  db.query(query, [name, email, id], (error, results) => {
      if (error) {
          return res.status(500).json({
              status: 'error',
              message: 'Error updating user',
              error: error
          });
      }

      // If no user found
      if (results.affectedRows === 0) {
          return res.status(404).json({
              status: 'error',
              message: 'User not found'
          });
      }

      // Return success
      res.status(200).json({
          status: 'success',
          message: 'User updated successfully'
      });
  });
});


router.delete('/deleteuser/:id', (req, res) => {
  const id = req.params.id;
  const query = 'DELETE FROM users WHERE id = ?';
  
  db.query(query, [id], (error, results) => {
      if (error) {
          return res.status(500).json({
              status: 'error',
              message: 'Error deleting user',
              error: error
          });
      }

      // If no user found
      if (results.affectedRows === 0) {
          return res.status(404).json({
              status: 'error',
              message: 'User not found'
          });
      }

      // Return success
      res.status(200).json({
          status: 'success',
          message: 'User deleted successfully'
      });
  });
});
module.exports = router;