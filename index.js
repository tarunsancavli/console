const express = require('express');

const errorFunction = require('./utils/error');

require('./config/db').connectDB();

const bodyParser = require('body-parser');

const routes = require('./routes/routes');

const cors = require('cors');

const passport = require('passport');

require('dotenv').config();

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));

app.use(bodyParser.json());

app.use(passport.initialize());

var corsOptions = {
    origin: "http://localhost:8080"
};

app.use(cors(corsOptions));

app.use(passport.initialize());

require('./middlewares/passport');

app.route('/', (req, res) => {
    res.status(200).json(
        errorFunction(false, "Home page", "Welcome to login, sign-up api")
    )
});

app.use('/api', routes);

const port = process.env.PORT || 8080;

app.listen(port, () => {
    console.log(`app running on port ${port}`);
}) 