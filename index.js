const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ggulbwq.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const userCollection = client.db("easyPay").collection("users");

    // Register user
    app.post("/register", async (req, res) => {
      const user = req.body;

      // already exists ?
      const existingUser = await userCollection.findOne({
        $or: [{ email: user.email }, { mobile: user.mobile }],
      });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
      }

      if (user.pin) {
        const salt = bcrypt.genSaltSync(10);
        user.pin = bcrypt.hashSync(user.pin, salt);
      }

      console.log("new user", user);
      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // Login user
    app.post("/login", async (req, res) => {
      const { identifier, pin } = req.body;

      // Find user by email or mobile
      const user = await userCollection.findOne({
        $or: [{ email: identifier }, { mobile: identifier }],
      });

      if (!user) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      // Check if PIN is correct
      const isPinValid = bcrypt.compareSync(pin, user.pin);
      if (!isPinValid) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      // Create JWT token
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });

      // Set token as a cookie
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
      });
      res.json({ message: "Logged in successfully" });
    });

    // JWT Middleware
    const verifyToken = (req, res, next) => {
      const token = req.cookies.token;
      if (!token) {
        return res.status(401).json({ message: "Access denied" });
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
      } catch (error) {
        res.status(400).json({ message: "Invalid token" });
      }
    };

    // Get user
    app.get("/users", verifyToken, async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    });

    // All transaction history
    app.get("/payment", verifyToken, async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    });

    // Connect the client to the server (optional starting in v4.7)
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("server is running ............");
});

app.listen(port, () => console.log(`server is running on port : ${port}`));
