import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { pool, initDb } from "./db.js";

const app = express();

// =========================
// MIDDLEWARE
// =========================

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*"
  })
);

app.use(express.json());
app.use(express.static("public"));

// =========================
// HEALTH CHECK
// =========================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "WorldConnect API"
  });
});

// =========================
// REGISTER
// =========================

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      country
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error:
          "Name, email, and password are required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters"
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email
      .toLowerCase()
      .trim();

    const cleanCountry =
      country?.trim() || null;

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE email = $1
      `,
      [cleanEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Email already registered"
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
        (
          name,
          email,
          password_hash,
          country
        )
      VALUES
        ($1, $2, $3, $4)
      RETURNING
        id,
        name,
        email,
        country,
        created_at
      `,
      [
        cleanName,
        cleanEmail,
        passwordHash,
        cleanCountry
      ]
    );

    return res.status(201).json({
      message:
        "Account created successfully",
      user: result.rows[0]
    });

  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    return res.status(500).json({
      error: "Registration failed"
    });
  }
});

// =========================
// LOGIN
// =========================

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error:
          "Email and password are required"
      });
    }

    const cleanEmail = email
      .toLowerCase()
      .trim();

    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        password_hash,
        country,
        created_at
      FROM users
      WHERE email = $1
      `,
      [cleanEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error:
          "Invalid email or password"
      });
    }

    const user = result.rows[0];

    const passwordMatch =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!passwordMatch) {
      return res.status(401).json({
        error:
          "Invalid email or password"
      });
    }

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({
        error:
          "Server authentication is not configured"
      });
    }

    const token = jwt.sign(
      {
        userId: user.id
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    delete user.password_hash;

    return res.json({
      message: "Login successful",
      token,
      user
    });

  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      error: "Login failed"
    });
  }
});

// =========================
// CURRENT USER
// =========================

app.get("/api/me", async (req, res) => {
  try {
    const authHeader =
      req.headers.authorization;

    if (
      !authHeader ||
      !authHeader.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        error: "Not authenticated"
      });
    }

    const token =
      authHeader.substring(7);

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({
        error:
          "Server authentication is not configured"
      });
    }

    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );

    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        country,
        created_at
      FROM users
      WHERE id = $1
      `,
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "User not found"
      });
    }

    return res.json({
      user: result.rows[0]
    });

  } catch (error) {
    console.error(
      "ME ERROR:",
      error
    );

    return res.status(401).json({
      error:
        "Invalid or expired session"
    });
  }
});

// =========================
// AUTHENTICATION HELPER
// =========================

function getUserIdFromToken(req) {
  const authHeader =
    req.headers.authorization;

  if (
    !authHeader ||
    !authHeader.startsWith("Bearer ")
  ) {
    return null;
  }

  const token =
    authHeader.substring(7);

  try {
    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );

    return decoded.userId;
  } catch {
    return null;
  }
}

// =========================
// GET WORLD FEED
// =========================

app.get("/api/posts", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        posts.id,
        posts.body,
        posts.created_at,
        users.id AS user_id,
        users.name,
        users.country,
        COUNT(likes.post_id)::int AS like_count,
        COUNT(comments.id)::int AS comment_count
      FROM posts
      JOIN users
        ON users.id = posts.user_id
      LEFT JOIN likes
        ON likes.post_id = posts.id
      LEFT JOIN comments
        ON comments.post_id = posts.id
      GROUP BY
        posts.id,
        users.id
      ORDER BY
        posts.created_at DESC
      LIMIT 100
      `
    );

    return res.json({
      posts: result.rows
    });

  } catch (error) {
    console.error(
      "GET POSTS ERROR:",
      error
    );

    return res.status(500).json({
      error: "Failed to load posts"
    });
  }
});

// =========================
// CREATE POST
// =========================

app.post("/api/posts", async (req, res) => {
  try {
    const userId =
      getUserIdFromToken(req);

    if (!userId) {
      return res.status(401).json({
        error: "Please login first"
      });
    }

    const body =
      typeof req.body.body === "string"
        ? req.body.body.trim()
        : "";

    if (!body) {
      return res.status(400).json({
        error:
          "Post cannot be empty"
      });
    }

    if (body.length > 5000) {
      return res.status(400).json({
        error:
          "Post is too long"
      });
    }

    const result = await pool.query(
      `
      INSERT INTO posts
        (user_id, body)
      VALUES
        ($1, $2)
      RETURNING
        id,
        user_id,
        body,
        created_at
      `,
      [userId, body]
    );

    const post = await pool.query(
      `
      SELECT
        posts.id,
        posts.body,
        posts.created_at,
        users.id AS user_id,
        users.name,
        users.country,
        0::int AS like_count,
        0::int AS comment_count
      FROM posts
      JOIN users
        ON users.id = posts.user_id
      WHERE posts.id = $1
      `,
      [result.rows[0].id]
    );

    return res.status(201).json({
      message: "Post created successfully",
      post: post.rows[0]
    });

  } catch (error) {
    console.error(
      "CREATE POST ERROR:",
      error
    );

    return res.status(500).json({
      error: "Failed to create post"
    });
  }
});

// =========================
// START SERVER
// =========================

const port =
  process.env.PORT || 3000;

initDb()
  .then(() => {
    app.listen(
      port,
      () => {
        console.log(
          `WorldConnect running on port ${port}`
        );
      }
    );
  })
  .catch((err) => {
    console.error(
      "Database initialization failed:",
      err
    );

    process.exit(1);
  });
app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      country
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error:
          "Name, email, and password are required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters"
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email
      .toLowerCase()
      .trim();

    const cleanCountry =
      country?.trim() || null;

    // Check existing account
    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE email = $1
      `,
      [cleanEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Email already registered"
      });
    }

    // Hash password
    const passwordHash =
      await bcrypt.hash(password, 10);

    // Create account
    const result = await pool.query(
      `
      INSERT INTO users
        (
          name,
          email,
          password_hash,
          country
        )
      VALUES
        ($1, $2, $3, $4)
      RETURNING
        id,
        name,
        email,
        country,
        created_at
      `,
      [
        cleanName,
        cleanEmail,
        passwordHash,
        cleanCountry
      ]
    );

    return res.status(201).json({
      message:
        "Account created successfully",
      user: result.rows[0]
    });

  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    return res.status(500).json({
      error: "Registration failed"
    });
  }
});

// =========================
// LOGIN
// =========================

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error:
          "Email and password are required"
      });
    }

    const cleanEmail = email
      .toLowerCase()
      .trim();

    // Find user
    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        password_hash,
        country,
        created_at
      FROM users
      WHERE email = $1
      `,
      [cleanEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error:
          "Invalid email or password"
      });
    }

    const user = result.rows[0];

    // Check password
    const passwordMatch =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!passwordMatch) {
      return res.status(401).json({
        error:
          "Invalid email or password"
      });
    }

    // Check JWT secret
    if (!process.env.JWT_SECRET) {
      console.error(
        "JWT_SECRET is missing"
      );

      return res.status(500).json({
        error:
          "Server authentication is not configured"
      });
    }

    // Create JWT
    const token = jwt.sign(
      {
        userId: user.id
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    // Never send password hash
    delete user.password_hash;

    return res.json({
      message: "Login successful",
      token,
      user
    });

  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      error: "Login failed"
    });
  }
});

// =========================
// CURRENT USER
// =========================

app.get("/api/me", async (req, res) => {
  try {
    const authHeader =
      req.headers.authorization;

    if (
      !authHeader ||
      !authHeader.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        error: "Not authenticated"
      });
    }

    const token =
      authHeader.substring(7);

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({
        error:
          "Server authentication is not configured"
      });
    }

    // Verify token
    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );

    // Get current user
    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        country,
        created_at
      FROM users
      WHERE id = $1
      `,
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "User not found"
      });
    }

    return res.json({
      user: result.rows[0]
    });

  } catch (error) {
    console.error(
      "ME ERROR:",
      error
    );

    return res.status(401).json({
      error:
        "Invalid or expired session"
    });
  }
});

// =========================
// START SERVER
// =========================

const port =
  process.env.PORT || 3000;

initDb()
  .then(() => {
    app.listen(
      port,
      () => {
        console.log(
          `WorldConnect running on port ${port}`
        );
      }
    );
  })
  .catch((err) => {
    console.error(
      "Database initialization failed:",
      err
    );

    process.exit(1);
  });
