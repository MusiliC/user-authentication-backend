const express = require("express");
const router = express.Router();
const usersController = require("../controller/usersController");

router
  .route("/")
  .get(usersController.getAllUsers)
  .post(usersController.createNewUser)
  .patch(usersController.updateUser)
  .delete(usersController.deleteUser);

router.route("/sign").post(usersController.login);
router.route("/refresh").get(usersController.refresh);
router.route("/logout").post(usersController.logOut);

module.exports = router;
