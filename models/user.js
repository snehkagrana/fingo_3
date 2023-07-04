//Model for user account

const mongoose = require("mongoose");
const user = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    role: String,
    score:[{
        skill: {
            type: String,
        },
        category: {
            type: String,
        },
        sub_category: {
            type: String,
        },
        points: {
            type: Number,
        }
    }],
    last_played: {
        skill: {
            type: String,
        },
        category: {
            type: String,
        },
        sub_category: {
            type: String,
        } 
    }, 
    password_reset_token: String
});

module.exports = mongoose.model("User", user);