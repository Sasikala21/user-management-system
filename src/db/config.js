require('dotenv').config();
const mongoose = require("mongoose");
const dbConnection = process.env.DB_CONNECTION;
const dbName = process.env.DB_NAME;
async function connectToDatabase() {
    try {
        const connectionUri = `${dbConnection}`;
        await mongoose.connect(connectionUri, {
            dbName: process.env.DB_NAME
        });
        console.log("Database Connected Successfully");
    } catch (err) {
        console.error("Error connecting to MongoDB:", err.message);
    }
}
connectToDatabase();