require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const authRouter = require('./controller/authController');
const authMiddleware = require("./middleware/authMiddleware");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));

app.use('/auth', authRouter);
app.get('/protected', authMiddleware, (req, res) => res.json({ data: 'Secure Data' }));

app.listen(process.env.PORT || 3000, () => console.log(`Server running at port: ${process.env.PORT}`));