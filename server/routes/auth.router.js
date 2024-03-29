const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User.model");

const router = express.Router();
const saltRounds = 10;

// POST  /auth/signup
// ...
router.post("/signup", (req, res, next) => {
	console.log("got to sign up route");
	console.log("got body", req.body);
	const { email, password, name } = req.body;
	console.log(email, password, name);
	// Check if the email or password or name is provided as an empty string
	if (email === "" || password === "" || name === "") {
		res.status(400).json({ message: "Provide email, password and name" });
		return;
	}

	const emailRegex = new RegExp(/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/);
	if (!emailRegex.test(email)) {
		res.status(400).json({ message: "email must be a valid email" });
		return;
	}

	const passwordRegex = new RegExp(/(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/);
	if (!passwordRegex.test(password)) {
		res.status(400).json({
			message:
				"Password must have at least 6 characters and contain at least one number, one lowercase and one uppercase letter.",
		});
		return;
	}

	User.findOne({ email })
		.then((foundUser) => {
			// If the user with the same email already exists, send an error response
			if (foundUser) {
				res.status(400).json({ message: "User already exists." });
				return;
			}

			// If the email is unique, proceed to hash the password
			const salt = bcrypt.genSaltSync(saltRounds);
			const hashedPassword = bcrypt.hashSync(password, salt);

			// Create a new user in the database
			// We return a pending promise, which allows us to chain another `then`
			return User.create({ email, password: hashedPassword, name });
		})
		.then((createdUser) => {
			// Deconstruct the newly created user object to omit the password
			// We should never expose passwords publicly
			const { email, name, _id } = createdUser;

			// Create a new object that doesn't expose the password
			const user = { email, name, _id };

			// Send a json response containing the user object
			res.status(201).json({ user: user });
		})
		.catch((err) => {
			console.log(err);
			res.status(500).json({ message: "Internal Server Error" });
		});
});

// POST  /auth/login
// ...

// GET  /auth/verify
// ...

module.exports = router;
