const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

const router = express.Router();

const saltRounds = 10;
const secret = process.env.JWT_SECRET;

router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ message: "Please provide a username and password" });
  }

  const exists = await prisma.user.findFirst({
    where: {
      username,
    },
  });

  if (exists) {
    res
      .status(401)
      .json({ error: "This username already exists. Please try another" });
  }

  // sync version
  // const salt = bcrypt.genSaltSync(saltRounds);
  // const hash = bcrypt.hashSync(password, salt);

  // async
  bcrypt.genSalt(saltRounds, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      const newUser = await prisma.user.create({
        data: {
          username,
          password: hash,
        },
      });

      delete newUser.password;

      res.status(201).json({ status: "success", user: newUser });
    });
  });

  // const newUser = await prisma.user.create({
  //   data: {
  //     username,
  //     password: hash,
  //   },
  // });

  // delete newUser.password;

  // res.status(201).json({ status: "success", user: newUser });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ error: "Please provide a username and password" });
  }

  const found = await prisma.user.findFirst({
    where: {
      username: username,
    },
  });

  if (!found) {
    return res
      .status(401)
      .json({ error: "Either the username or password is incorrect" });
  }

  // sync version
  // const match = bcrypt.compareSync(password, found.password);

  // if (!match) {
  //   return res
  //     .status(401)
  //     .json({ error: "Either the username or password is incorrect" });
  // }

  // const token = jwt.sign({ username }, secret);

  // res.json({ token });

  // async version
  bcrypt.compare(password, found.password, (err, match) => {
    if (!match) {
      return res
        .status(401)
        .json({ error: "Either the username or password is incorrect" });
    }

    const token = jwt.sign({ username }, secret);
    res.json({ token });
  });
});

module.exports = router;
