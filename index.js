// app.js or server.js
const express = require('express');
const cors = require('cors');
const db = require('./db');


const app = express();
const port = process.env.PORT || 5000;


// Middleware
app.use(express.json());
app.use(cors());

// Routes
app.use('/api/auth', require('./routes/auth'));

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});