const otpGenerator = require('otp-generator')

module.exports.otpGenerator = () => {
    try {
        const otp = otpGenerator.generate(4,{
            digits: true,
            lowerCaseAlphabets: false,
            upperCaseAlphabets: false,
            specialChars: false 
        });
        return otp;
    } catch (error) {
        return error.message;
    }
}
    