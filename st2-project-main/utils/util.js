const nodemailer = require('nodemailer');
require('dotenv').config();

module.exports.SendEmail = async (email, subject, text) => {
    try {
        const transporter = nodemailer.createTransport({
            // host: "smtp.forwardemail.net",
            service: "gmail",
            // port: 465,
            // secure: true,
            auth: {
                user: process.env.USER,
                pass: process.env.PASS,
            },
            authMethod: "PLAIN"
        });
        await transporter.sendMail({
            from: process.env.USER,
            to: email,
            subject: subject,
            text: text,
        })
    } catch (error) {
        console.log("email not sent");
        console.log(error);
    }
}