require('dotenv').config();
const emailConfig = {
    host: process.env.HOST,
    secure: false,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
    },
};

module.exports = emailConfig;