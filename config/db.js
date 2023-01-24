const MongoClient = require('mongodb').MongoClient;

require('dotenv').config();

let _db;

const connectDB = async () => {
  try {
    const client = await MongoClient.connect(process.env.MONGO_URI, { useNewUrlParser: true });
    _db = client.db();
    console.log('Connected to Database...');
  } catch (err) {
    console.log(err);
  }
};

const getDB = () => {
  if (_db) {
    return _db;
  }
  throw 'No database found!';
};

module.exports = { connectDB, getDB };
