const express = require('express');

const bodyParser = require('body-parser');

const routes = require('./routes/routes');

const cors = require('cors');

require('dotenv').config();

const app = express();

require('./config/db').connectDB();

app.use(bodyParser.urlencoded({extended: false}));

app.use(bodyParser.json());

var corsOptions = {
    origin: "http://localhost:8080"
  };
  
app.use(cors(corsOptions));

app.route('/',(req,res) => {
    res.status(200).send(`Welcome to login, sign-up api`);
})

app.use('/api', routes);

const port = process.env.PORT || 8080;

app.listen(port,() => {
    console.log(`app running on port ${port}`);
})