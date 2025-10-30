// Sample middleware
module.exports = (req, res, next) => {
    console.log('Sample middleware executed');
    next();
};