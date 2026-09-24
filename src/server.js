import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { pool, initDb } from "./db.js";

const app = express();

app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

// =========================
// AUTH HELPERS
// =========================

function tokenFor(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    const token = header.slice(7);

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

// =========================
// HEALTH
// =========================

app.get("/api/health", (_, res) => {
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
    const { name, email, password, country } = req.body;

    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "").toLowerCase().trim();
    const cleanCountry = String(country || "").trim();

    if (!cleanName || !cleanEmail || !password) {
      return res.status(400).json({
        error: "Name, email and password are required"
      });
    }

    if (cleanName.length > 80) {
      return res.status(400).json({
        error: "Name is too long"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const q = await pool.query(
      `
      INSERT INTO users
        (name, email, password_hash, country)
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
        hash,
        cleanCountry || null
      ]
    );

    const user = q.rows[0];

    res.status(201).json({
      user,
      token: tokenFor(user)
    });

  } catch (e) {

    if (e.code === "23505") {
      return res.status(409).json({
        error: "Email is already registered"
      });
    }

    console.error("REGISTER ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// LOGIN
// =========================

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .toLowerCase()
      .trim();

    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required"
      });
    }

    const q = await pool.query(
      `
      SELECT *
      FROM users
      WHERE email = $1
      `,
      [email]
    );

    const user = q.rows[0];

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    delete user.password_hash;

    res.json({
      user,
      token: tokenFor(user)
    });

  } catch (e) {

    console.error("LOGIN ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// CURRENT USER
// =========================

app.get("/api/me", auth, async (req, res) => {
  try {

    const q = await pool.query(
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
      [req.user.id]
    );

    if (!q.rows[0]) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    res.json(q.rows[0]);

  } catch (e) {

    console.error("ME ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// POSTS / FEED
// =========================

app.get("/api/posts", async (req, res) => {
  try {

    let currentUserId = null;

    // If logged in, detect which posts the user liked
    try {
      const header = req.headers.authorization || "";

      if (header.startsWith("Bearer ")) {
        const decoded = jwt.verify(
          header.slice(7),
          JWT_SECRET
        );

        currentUserId = Number(decoded.id);
      }
    } catch {
      currentUserId = null;
    }

    const q = await pool.query(
      `
      SELECT
        p.id,
        p.body,
        p.created_at,

        u.id AS user_id,
        u.name,
        u.country,

        (
          SELECT COUNT(*)
          FROM likes l
          WHERE l.post_id = p.id
        )::int AS likes,

        (
          SELECT COUNT(*)
          FROM comments c
          WHERE c.post_id = p.id
        )::int AS comments,

        CASE
          WHEN $1::bigint IS NULL THEN false
          WHEN EXISTS (
            SELECT 1
            FROM likes my_like
            WHERE my_like.post_id = p.id
              AND my_like.user_id = $1
          )
          THEN true
          ELSE false
        END AS liked

      FROM posts p

      JOIN users u
        ON u.id = p.user_id

      ORDER BY p.created_at DESC

      LIMIT 50
      `,
      [currentUserId]
    );

    res.json(q.rows);

  } catch (e) {

    console.error("GET POSTS ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// CREATE POST
// =========================

app.post("/api/posts", auth, async (req, res) => {
  try {

    const body = String(req.body.body || "").trim();

    if (!body) {
      return res.status(400).json({
        error: "Post cannot be empty"
      });
    }

    if (body.length > 5000) {
      return res.status(400).json({
        error: "Post is too long"
      });
    }

    const q = await pool.query(
      `
      INSERT INTO posts
        (user_id, body)
      VALUES
        ($1, $2)
      RETURNING
        id,
        body,
        created_at
      `,
      [
        req.user.id,
        body
      ]
    );

    res.status(201).json(q.rows[0]);

  } catch (e) {

    console.error("CREATE POST ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// LIKE / UNLIKE
// =========================

app.post("/api/posts/:id/like", auth, async (req, res) => {
  try {

    const postId = Number(req.params.id);

    if (!Number.isInteger(postId) || postId <= 0) {
      return res.status(400).json({
        error: "Invalid post ID"
      });
    }

    // Check if already liked
    const existing = await pool.query(
      `
      SELECT 1
      FROM likes
      WHERE user_id = $1
        AND post_id = $2
      `,
      [
        req.user.id,
        postId
      ]
    );

    let liked;

    if (existing.rowCount > 0) {

      // Unlike
      await pool.query(
        `
        DELETE FROM likes
        WHERE user_id = $1
          AND post_id = $2
        `,
        [
          req.user.id,
          postId
        ]
      );

      liked = false;

    } else {

      // Like
      await pool.query(
        `
        INSERT INTO likes
          (user_id, post_id)
        VALUES
          ($1, $2)
        ON CONFLICT (user_id, post_id)
        DO NOTHING
        `,
        [
          req.user.id,
          postId
        ]
      );

      liked = true;
    }

    const count = await pool.query(
      `
      SELECT COUNT(*)::int AS likes
      FROM likes
      WHERE post_id = $1
      `,
      [postId]
    );

    res.json({
      liked,
      likes: count.rows[0].likes
    });

  } catch (e) {

    console.error("LIKE ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// GET COMMENTS
// =========================

app.get("/api/posts/:id/comments", async (req, res) => {
  try {

    const postId = Number(req.params.id);

    if (!Number.isInteger(postId) || postId <= 0) {
      return res.status(400).json({
        error: "Invalid post ID"
      });
    }

    const q = await pool.query(
      `
      SELECT
        c.id,
        c.body,
        c.created_at,

        u.id AS user_id,
        u.name,
        u.country

      FROM comments c

      JOIN users u
        ON u.id = c.user_id

      WHERE c.post_id = $1

      ORDER BY c.created_at ASC
      `,
      [postId]
    );

    res.json(q.rows);

  } catch (e) {

    console.error("GET COMMENTS ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// CREATE COMMENT
// =========================

app.post("/api/posts/:id/comment", auth, async (req, res) => {
  try {

    const postId = Number(req.params.id);
    const body = String(req.body.body || "").trim();

    if (!Number.isInteger(postId) || postId <= 0) {
      return res.status(400).json({
        error: "Invalid post ID"
      });
    }

    if (!body || body.length > 1000) {
      return res.status(400).json({
        error: "Comment must be 1-1000 characters"
      });
    }

    // Make sure post exists
    const post = await pool.query(
      `
      SELECT id
      FROM posts
      WHERE id = $1
      `,
      [postId]
    );

    if (post.rowCount === 0) {
      return res.status(404).json({
        error: "Post not found"
      });
    }

    const q = await pool.query(
      `
      INSERT INTO comments
        (user_id, post_id, body)
      VALUES
        ($1, $2, $3)
      RETURNING
        id,
        body,
        created_at
      `,
      [
        req.user.id,
        postId,
        body
      ]
    );
// Create notification for the post owner
const postOwner = await pool.query(
  `
  SELECT user_id
  FROM posts
  WHERE id = $1
  `,
  [postId]
);

if (
  postOwner.rowCount > 0 &&
  postOwner.rows[0].user_id !== req.user.id
) {
  await pool.query(
    `
    INSERT INTO notifications
      (user_id, actor_id, type, post_id, message)
    VALUES
      ($1, $2, $3, $4, $5)
    `,
    [
      postOwner.rows[0].user_id,
      req.user.id,
      "comment",
      postId,
      "Someone commented on your post."
    ]
  );
}
    res.status(201).json(q.rows[0]);

  } catch (e) {

    console.error("CREATE COMMENT ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});


// =========================
// FOLLOW / UNFOLLOW
// =========================

app.post("/api/users/:id/follow", auth, async (req, res) => {
  try {

    const userId = Number(req.params.id);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        error: "Invalid user ID"
      });
    }

    if (userId === Number(req.user.id)) {
      return res.status(400).json({
        error: "You cannot follow yourself"
      });
    }

    // Check target user
    const target = await pool.query(
      `
      SELECT id
      FROM users
      WHERE id = $1
      `,
      [userId]
    );

    if (target.rowCount === 0) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    // Check existing follow
    const existing = await pool.query(
      `
      SELECT 1
      FROM follows
      WHERE follower_id = $1
        AND following_id = $2
      `,
      [
        req.user.id,
        userId
      ]
    );

    let following;

    if (existing.rowCount > 0) {

      // Unfollow
      await pool.query(
        `
        DELETE FROM follows
        WHERE follower_id = $1
          AND following_id = $2
        `,
        [
          req.user.id,
          userId
        ]
      );

      following = false;

    } else {

      // Follow
      await pool.query(
        `
        INSERT INTO follows
          (follower_id, following_id)
        VALUES
          ($1, $2)
        ON CONFLICT DO NOTHING
        `,
        [
          req.user.id,
          userId
        ]
      );

      following = true;
    }

    res.json({
      following
    });

  } catch (e) {

    console.error("FOLLOW ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// USER PROFILE
// =========================

app.get("/api/users/:id", async (req, res) => {
  try {

    const userId = Number(req.params.id);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        error: "Invalid user ID"
      });
    }

    const q = await pool.query(
      `
      SELECT
        u.id,
        u.name,
        u.email,
        u.country,
        u.created_at,

        (
          SELECT COUNT(*)
          FROM posts p
          WHERE p.user_id = u.id
        )::int AS posts,

        (
          SELECT COUNT(*)
          FROM follows f
          WHERE f.following_id = u.id
        )::int AS followers,

        (
          SELECT COUNT(*)
          FROM follows f
          WHERE f.follower_id = u.id
        )::int AS following

      FROM users u

      WHERE u.id = $1
      `,
      [userId]
    );

    if (q.rowCount === 0) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    res.json(q.rows[0]);

  } catch (e) {

    console.error("USER PROFILE ERROR:", e);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// GET NOTIFICATIONS
// =========================

app.get("/api/notifications", auth, async (req, res) => {
  try {

    const q = await pool.query(
      `
      SELECT
        n.id,
        n.type,
        n.message,
        n.post_id,
        n.is_read,
        n.created_at,
        u.name AS actor_name,
        u.country AS actor_country

      FROM notifications n

      LEFT JOIN users u
        ON u.id = n.actor_id

      WHERE n.user_id = $1

      ORDER BY n.created_at DESC

      LIMIT 50
      `,
      [req.user.id]
    );

    res.json(q.rows);

  } catch (e) {

    console.error(
      "GET NOTIFICATIONS ERROR:",
      e
    );

    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// START SERVER
// =========================

const port = process.env.PORT || 3000;

initDb()
  .then(() => {
    app.listen(port, () => {
      console.log(`WorldConnect running on port ${port}`);
    });
  })
  .catch((err) => {
    console.error(
      "Database initialization failed:",
      err
    );

    process.exit(1);
  });
