const express = require('express');
const session = require('express-session');
const authRoutes = require('./routes/auth');
require('dotenv').config();

const app = express();
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // true ถ้าใช้ https
      httpOnly: true,
      maxAge: 1000 * 60 * 60, // 1 ชม.
    },
  })
);

app.use('/api', authRoutes);

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
