const rateLimit = require("express-rate-limit");
const { logEvents } = require("./logger");

const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // limit each ip to 5 login requests per window per minute
  message: {
    message: "Too many login attempts from this IP, try again after sometime",
    handler: (req, res, next, options) => {
      logEvents(
        `Too many requests: ${options.message.message}\t ${req.method}\t${req.url}\t${req.headers.origin}`,
        "errorLog.log"
      );
      res.status(options.statusCode).send(options.message);
    },
    standardHeaders: true, //return late limit info in the `Rate Limit`
    legacyHeaders: false, //disable the `X-rate limit` headers
  },
});

module.exports = loginLimiter;
