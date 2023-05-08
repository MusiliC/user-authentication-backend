require("dotenv").config();
const express = require("express");
const app = express();
const path = require("path");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose")
const PORT = process.env.PORT || 3500;
const cors = require("cors");
const corsOptions = require("./config/corsOptions")
const { logger } = require("./middleware/logger");
const errorHandler = require("./middleware/errorHandler");
const connectDb = require("./config/dbCon")

//connect db

connectDb();

//cors

app.use(cors(corsOptions));

//custom middleware
app.use(logger);

//middleware for json
app.use(express.json());
app.use(cookieParser());

//static files
app.use(express.static(path.join(__dirname, "public")));

//routes
app.use("/", require("./routes/root"));

app.use("/users", require("./routes/userRoutes"))

app.get("/*", (req, res) => {
  res.status(404);
  if (req.accepts("html")) {
    res.sendFile(path.join(__dirname, "views", "404.html"));
  } else if (req.accepts("json")) {
    res.json({ message: "404 Not Found" });
  } else {
    res.type("txt").send("404 Not found..");
  }
});

app.use(errorHandler);

mongoose.connection.once("open", () => {
  console.log("Connected to Mongo DB..");
  app.listen(PORT, () => {
    console.log(`Listening to port ${PORT}`);
  });
})


