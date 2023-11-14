import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

// Register User
export const register = async (req, res) => { // Need to asynchronous because it is calling to mongoose database (rec = request, res = response)
    try {
        const { // Use parameters and send them to the function
            firstName, 
            lastName,
            email,
            password,
            picturePath,
            friends,
            location,
            occupation
        } = req.body;

        const salt = await bcrypt.genSalt(); //Random salt to encrypt the password
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = new User( {
            firstName, 
            lastName,
            email,
            password: passwordHash,
            picturePath,
            friends,
            location,
            occupation,
            viewedProfile: Math.floor(Math.random() * 10000),
            impressions: Math.floor(Math.random() * 10000)
        });
        const savedUser = await newUser.save(); // Saves new user
        res.status(201).json(savedUser); // Send a status code showing something is created

    } catch (err) {
        res.status(500).json({error: err.message });
    }
};

// Logging In
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email:email });
        if (!user) return res.status(400).json({ msg: "User does not exist. "});

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: "Invalid credentials. "});

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        delete user.password; // Deleted so it is not sent to the front-end (kept safe)
        res.status(200).json( {token, user });

    } catch (err) {
        res.status(500).json({error: err.message });
    }
}