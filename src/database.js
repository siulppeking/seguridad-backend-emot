const mongoose = require('mongoose');

const connectDatabase = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Database is connected');
    } catch (error) {
        console.log(error);
    }
}

module.exports = connectDatabase