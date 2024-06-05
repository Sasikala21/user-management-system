const bcrypt = require("bcryptjs");

const securePassword = async (password) => {
    const salt = await bcrypt.genSalt(8);
    const hashedPassword = await bcrypt.hash(password, 	salt);
    return hashedPassword;
};
module.exports = securePassword;