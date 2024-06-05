const express = require('express');
const bodyparser = require('body-parser');
const app = express();
const db = require("./src/db/config");
const UserRoute = require('./src/routes/user.route');

app.use(bodyparser.urlencoded({ extended: true }));
app.use(bodyparser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use('/api', UserRoute);

app.get("/", (req, res) => {
  res.json({ message: "Welcome to User Management System." });
});
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log("Server is listening on port", `${PORT}`);
});