const UserModel = require('../models/user.model');
const securePassword = require('../middlewares/bcrypt');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authJWT = require('../middlewares/authJWT.js');
exports.registerUser = async (req, res) => {
    try {
        const existingUser = await UserModel.findOne({ username: req.body.username });
        if (existingUser) {
            res.status(409).send({ status: 'Failure', statusCode: 409, error: "Username already exists" });
        }
        else {
            if (req.body.password !== req.body.confirmPassword) {
                return res.status(400).send({ status: 'Failure', statusCode: 400, message: 'Password & Confirm Password does not match!' });
            }
            else {
                const hashedPassword = await securePassword(req.body.password);
                const user = {
                    username: req.body.username,
                    email: req.body.email,
                    password: hashedPassword,
                    confirmPassword: hashedPassword,
                };
                await UserModel.create(user);
                return res.status(201).send({ status: 'Success', statusCode: 201, message: "User created successfully!!" });
            }
        }
    } catch (error) {
        return res.status(500).send({ status: 'Failure', statusCode: 500, message: error.message });
    }
}

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(401).send({ status: 'Failure!', statusCode: 401, message: 'Invalid Email' });
        } else {
            const isPasswordMatch = await bcrypt.compare(password, user.password);
            if (!isPasswordMatch) {
                return res.status(401).send({ status: 'Failure', statusCode: 401, message: 'Invalid Password' });
            } else {
                const accessToken = jwt.sign({ _id: user._id },
                    process.env.SECRET_KEY, {
                    expiresIn: '15m', // 15 min
                });
                const refreshToken = jwt.sign({ _id: user._id },
                    process.env.SECRET_KEY, {
                    expiresIn: '1d', // 1 day 
                });
                return res.status(200).send({
                    statusCode: 200,
                    message: "Login Successfully",
                    accessToken: accessToken,
                    refreshToken: refreshToken
                })
            }
        }
    } catch (error) {
        return res.status(500).send({ status: 'Failure', statusCode: 500, message: "Internal Server Error" });
    }
}

exports.userProfile = async (req, res) => {
    try {
        const user = await UserModel.findById(req.userId);
        if (!user) {
            return res.status(404).send({ status: 'Failure', statusCode: 404, message: 'User not found' });
        } else {
            const userData = {
                "userId": user._id,
                "username": user.username,
                "email": user.email
            }
            return res.status(200).send({ userDetails: userData, status: 'Success', statusCode: 200, message: 'User Details Fetched Successfully!' });
        }
    } catch {
        return res.status(500).send({ status: 'Failure', statusCode: 500, message: "Internal Server Error" });
    }
}

exports.logout = async (req, res) => {
    try {
        authJWT.invalidateToken(req.token);
        return res.status(200).send({ status: 'Success', statusCode: 200, message: "User Logged Out Successfully" });
    } catch (error) {
        return res.status(500).send({ status: 'Failure', statusCode: 500, message: "Internal Server Error" });
    }
}