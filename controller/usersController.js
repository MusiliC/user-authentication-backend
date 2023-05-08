const User = require("../models/User");
const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

//get users
const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find().select("-password").lean();
  if (!users?.length) {
    return res.status(400).json({ message: "No users found" });
  }
  res.json(users);
});

//create user
const createNewUser = asyncHandler(async (req, res) => {
  const { username, password, roles } = req.body;

  //confirm data
  if (!username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  //check for duplicates

  const duplicate = await User.findOne({ username })
    .collation({ locale: "en", strength: 2 })
    .lean()
    .exec();

  if (duplicate) {
    return res.status(409).json({ message: "Duplicate username" });
  }

  //hash password

  const hashedPassword = await bcrypt.hash(password, 10);

  const userObject =
    !Array.isArray(roles) || !roles.length
      ? {
          username,
          password: hashedPassword,
        }
      : {
          username,
          password: hashedPassword,
          roles,
        };

  //create and store new user

  const user = await User.create(userObject);

  if (user) {
    res.status(201).json({ message: `New user ${username} created..` });
  } else {
    res.status(400).json({ message: `invalid user data received` });
  }
});

//desc login
//route post/users
//access public

const login = asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  //confirm data
  if (!username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const foundUser = await User.findOne({ username }).exec();

  if (!foundUser) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const match = await bcrypt.compare(password, foundUser.password);

  if (!match) return res.status(401).json({ message: "unauthorized" });

  const accessToken = jwt.sign(
    {
      UserInfo: {
        username: foundUser.username,
        roles: foundUser.roles,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "10s" }
  );

  const refreshToken = jwt.sign(
    { username: foundUser.username },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "15s" }
  );

  //create secure cookie with refresh token

  res.cookie("jwt", refreshToken, {
    httpOnly: true, //only accessible by web server
    secure: true, //https
    sameSite: "None", //cross-site cookie
    maxAge: 7 * 24 * 60 * 60 * 100, //cookie expiry
  });

  //send access token containing username and roles

  res.json({ accessToken });
});

//desc refresh
//route get /auth/refresh
// access public because access token has expired

const refresh = (req, res) => {
  const cookies = req.cookies;

  if (!cookies?.jwt) return res.status(401).json({ message: "unauthorized" });

  const refreshToken = cookies.jwt;

  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    asyncHandler(async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Forbidden" });

      const foundUser = await User.findOne({
        username: decoded.username,
      }).exec();

      if (!foundUser) return res.status(401).json({ message: "Unauthorized" });

      const accessToken = jwt.sign(
        {
          UserInfo: {
            username: foundUser.username,
            roles: foundUser.roles,
          },
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15s" }
      );

      res.json({ accessToken });
    })
  );
};

//log out
// post/ auth/logout
//public - to clear cookie if exists

const logOut = (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204); //No content
  res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });
  res.json({ message: "Cookie cleared" });
};

//update user
const updateUser = asyncHandler(async (req, res) => {
  const { id, username, roles, password } = req.body;

  //confirm data

  if (!id || !username || !Array.isArray(roles) || !roles.length) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const user = await User.findById(id).exec();

  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  //check for duplicate

  const duplicate = await User.findOne({ username })
    .collation({ locale: "en", strength: 2 })
    .lean()
    .exec();

  //allow updates to the original user

  if (duplicate && duplicate?._id.toString() !== id) {
    return res.status(409).json({ message: "Duplicate username" });
  }

  user.username = username;
  user.roles = roles;

  if (password) {
    //hash password
    user.password = await bcrypt.hash(password, 10);
  }

  const updatedUser = await user.save();

  res.json({ message: `User ${updatedUser.username} updated` });
});

//delete user
const deleteUser = asyncHandler(async (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res.status(400).json({ message: "user ID is required" });
  }

  const user = await User.findById(id).exec();

  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  const result = await user.deleteOne();

  const reply = `Username ${result.username} with ID ${result._id} deleted`;

  res.json(reply);
});

module.exports = {
  getAllUsers,
  createNewUser,
  updateUser,
  deleteUser,
  login,
  refresh,
  logOut,
};
