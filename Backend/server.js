const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5050;

app.use(cors());
app.use(express.json());

let users = [
  {
    id: 1,
    fullname: "Admin User",
    email: "admin@eventhub.com",
    password: "admin123",
    role: "admin"
  },
  {
    id: 2,
    fullname: "Host User",
    email: "host@eventhub.com",
    password: "host123",
    role: "host"
  },
  {
    id: 3,
    fullname: "Regular User",
    email: "user@eventhub.com",
    password: "user123",
    role: "user"
  }
];

let events = [
  {
    id: 1,
    title: "Music Festival",
    date: "2026-07-20",
    location: "Newark, NJ",
    description: "A live outdoor music event with multiple artists.",
    createdBy: "host@eventhub.com"
  },
  {
    id: 2,
    title: "Business Conference",
    date: "2026-08-02",
    location: "Jersey City, NJ",
    description: "A networking and business strategy conference.",
    createdBy: "host@eventhub.com"
  }
];

/* Test route */
app.get("/", (req, res) => {
  res.json({ message: "EventHub backend is running" });
});

/* Get all events */
app.get("/api/events", (req, res) => {
  res.json(events);
});

/* Register */
app.post("/api/register", (req, res) => {
  const { fullname, email, password, confirmPassword, role } = req.body;

  if (!fullname || !email || !password || !confirmPassword || !role) {
    return res.status(400).json({
      message: "Please fill in all fields"
    });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({
      message: "Passwords do not match"
    });
  }

  const validRoles = ["user", "host", "admin"];
  if (!validRoles.includes(role)) {
    return res.status(400).json({
      message: "Invalid role selected"
    });
  }

  const existingUser = users.find((user) => user.email === email);

  if (existingUser) {
    return res.status(409).json({
      message: "User already exists"
    });
  }

  const newUser = {
    id: users.length + 1,
    fullname,
    email,
    password,
    role
  };

  users.push(newUser);

  res.status(201).json({
    message: "Registration successful",
    user: {
      id: newUser.id,
      fullname: newUser.fullname,
      email: newUser.email,
      role: newUser.role
    }
  });
});

/* Login */
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Please enter email and password"
    });
  }

  const user = users.find(
    (u) => u.email === email && u.password === password
  );

  if (!user) {
    return res.status(401).json({
      message: "Invalid email or password"
    });
  }

  res.json({
    message: "Login successful",
    user: {
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      role: user.role
    }
  });
});

/* Host or Admin can create events */
app.post("/api/events", (req, res) => {
  const { title, date, location, description, createdBy } = req.body;

  if (!title || !date || !location || !description || !createdBy) {
    return res.status(400).json({
      message: "Please fill in all event fields"
    });
  }

  const creator = users.find((user) => user.email === createdBy);

  if (!creator) {
    return res.status(404).json({
      message: "User not found"
    });
  }

  if (creator.role !== "host" && creator.role !== "admin") {
    return res.status(403).json({
      message: "Only hosts or admins can create events"
    });
  }

  const newEvent = {
    id: events.length + 1,
    title,
    date,
    location,
    description,
    createdBy
  };

  events.push(newEvent);

  res.status(201).json({
    message: "Event created successfully",
    event: newEvent
  });
});

/* Admin can view all users */
app.get("/api/users", (req, res) => {
  res.json(users.map(user => ({
    id: user.id,
    fullname: user.fullname,
    email: user.email,
    role: user.role
  })));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});