const errorFunction = (error, msg, data) => {
    if (error) return { is_error: error, message: msg };
    else return msg, data;
};

module.exports = errorFunction;