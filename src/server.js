import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import { pool, initDb } from "./db.js";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET || "worldconnect-development-secret";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());

app.use(
  express.json({
    limit: "2mb"
  })
);


/* =====================================================
   AUTH HELPERS
===================================================== */

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}


function getTokenFromRequest(req) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return null;
  }

  return auth.substring(7);
}


function requireAuth(req, res, next) {
  try {
    const token = getTokenFromRequest(req);

    if (!token) {
      return res.status(401).json({
        error: "Authentication required."
      });
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    req.user = decoded;

    next();

  } catch (error) {

    return res.status(401).json({
      error: "Invalid or expired token."
    });
  }
}


/* =====================================================
   HEALTH
===================================================== */

app.get("/api/health", async (req, res) => {

  try {

    await pool.query("SELECT 1");

    res.json({
      ok: true,
      service: "WorldConnect API"
    });

  } catch (error) {

    console.error(
      "HEALTH ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      error: "Database connection failed."
    });
  }
});


/* =====================================================
   REGISTER
===================================================== */

app.post(
  "/api/auth/register",
  async (req, res) => {

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
            "Name, email and password are required."
        });
      }

      if (password.length < 6) {

        return res.status(400).json({
          error:
            "Password must be at least 6 characters."
        });
      }

      const cleanName =
        String(name).trim();

      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();

      const existing =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE email = $1
          `,
          [cleanEmail]
        );

      if (existing.rows.length > 0) {

        return res.status(409).json({
          error:
            "Email is already registered."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          10
        );

      const result =
        await pool.query(
          `
          INSERT INTO users
            (
              name,
              email,
              password_hash,
              country
            )
          VALUES
            (
              $1,
              $2,
              $3,
              $4
            )
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
            country
              ? String(country).trim()
              : null
          ]
        );

      const user =
        result.rows[0];

      const token =
        createToken(user);

      res.status(201).json({
        token,
        user
      });

    } catch (error) {

      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Registration failed."
      });
    }
  }
);


/* =====================================================
   LOGIN
===================================================== */

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      const {
        email,
        password
      } = req.body;

      if (!email || !password) {

        return res.status(400).json({
          error:
            "Email and password are required."
        });
      }

      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();

      const result =
        await pool.query(
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
            "Invalid email or password."
        });
      }

      const user =
        result.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {

        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      delete user.password_hash;

      const token =
        createToken(user);

      res.json({
        token,
        user
      });

    } catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Login failed."
      });
    }
  }
);


/* =====================================================
   CURRENT USER
===================================================== */

app.get(
  "/api/me",
  requireAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
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

      if (result.rows.length === 0) {

        return res.status(404).json({
          error:
            "User not found."
        });
      }

      res.json({
        user:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "ME ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load user."
      });
    }
  }
);


/* =====================================================
   GET WORLD FEED
===================================================== */

app.get(
  "/api/posts",
  requireAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            p.id,
            p.body,
            p.created_at,

            u.id AS user_id,
            u.name,
            u.country,

            COUNT(
              DISTINCT l.user_id
            )::int AS like_count,

            COUNT(
              DISTINCT c.id
            )::int AS comment_count,

            EXISTS (
              SELECT 1
              FROM likes my_like
              WHERE my_like.post_id = p.id
                AND my_like.user_id = $1
            ) AS liked_by_me

          FROM posts p

          JOIN users u
            ON u.id = p.user_id

          LEFT JOIN likes l
            ON l.post_id = p.id

          LEFT JOIN comments c
            ON c.post_id = p.id

          GROUP BY
            p.id,
            p.body,
            p.created_at,
            u.id,
            u.name,
            u.country

          ORDER BY
            p.created_at DESC

          LIMIT 100
          `,
          [req.user.id]
        );

      res.json({
        posts:
          result.rows
      });

    } catch (error) {

      console.error(
        "GET POSTS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load posts."
      });
    }
  }
);


/* =====================================================
   CREATE POST
===================================================== */

app.post(
  "/api/posts",
  requireAuth,
  async (req, res) => {

    try {

      const body =
        String(
          req.body.body || ""
        ).trim();

      if (!body) {

        return res.status(400).json({
          error:
            "Post cannot be empty."
        });
      }

      if (body.length > 5000) {

        return res.status(400).json({
          error:
            "Post is too long."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO posts
            (
              user_id,
              body
            )
          VALUES
            (
              $1,
              $2
            )
          RETURNING
            id,
            user_id,
            body,
            created_at
          `,
          [
            req.user.id,
            body
          ]
        );

      res.status(201).json({
        post:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "CREATE POST ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to create post."
      });
    }
  }
);


/* =====================================================
   LIKE / UNLIKE POST
===================================================== */

app.post(
  "/api/posts/:id/like",
  requireAuth,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const postId =
        Number(req.params.id);

      if (!Number.isInteger(postId)) {

        return res.status(400).json({
          error:
            "Invalid post ID."
        });
      }

      await client.query(
        "BEGIN"
      );

      const postResult =
        await client.query(
          `
          SELECT
            id,
            user_id
          FROM posts
          WHERE id = $1
          `,
          [postId]
        );

      if (
        postResult.rows.length === 0
      ) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          error:
            "Post not found."
        });
      }

      const existing =
        await client.query(
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

      if (
        existing.rows.length > 0
      ) {

        await client.query(
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

        await client.query(
          `
          INSERT INTO likes
            (
              user_id,
              post_id
            )
          VALUES
            (
              $1,
              $2
            )
          `,
          [
            req.user.id,
            postId
          ]
        );

        liked = true;
      }

      const countResult =
        await client.query(
          `
          SELECT
            COUNT(*)::int AS count
          FROM likes
          WHERE post_id = $1
          `,
          [postId]
        );

      await client.query(
        "COMMIT"
      );

      res.json({
        liked,
        like_count:
          countResult.rows[0].count
      });

    } catch (error) {

      await client.query(
        "ROLLBACK"
      );

      console.error(
        "LIKE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to update like."
      });

    } finally {

      client.release();
    }
  }
);


/* =====================================================
   GET COMMENTS
===================================================== */

app.get(
  "/api/posts/:id/comments",
  requireAuth,
  async (req, res) => {

    try {

      const postId =
        Number(req.params.id);

      if (!Number.isInteger(postId)) {

        return res.status(400).json({
          error:
            "Invalid post ID."
        });
      }

      const result =
        await pool.query(
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

          ORDER BY
            c.created_at ASC

          LIMIT 200
          `,
          [postId]
        );

      res.json({
        comments:
          result.rows
      });

    } catch (error) {

      console.error(
        "GET COMMENTS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load comments."
      });
    }
  }
);


/* =====================================================
   ADD COMMENT
===================================================== */

app.post(
  "/api/posts/:id/comments",
  requireAuth,
  async (req, res) => {

    try {

      const postId =
        Number(req.params.id);

      const body =
        String(
          req.body.body || ""
        ).trim();

      if (!Number.isInteger(postId)) {

        return res.status(400).json({
          error:
            "Invalid post ID."
        });
      }

      if (!body) {

        return res.status(400).json({
          error:
            "Comment cannot be empty."
        });
      }

      if (body.length > 1000) {

        return res.status(400).json({
          error:
            "Comment is too long."
        });
      }

      const post =
        await pool.query(
          `
          SELECT id
          FROM posts
          WHERE id = $1
          `,
          [postId]
        );

      if (
        post.rows.length === 0
      ) {

        return res.status(404).json({
          error:
            "Post not found."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO comments
            (
              user_id,
              post_id,
              body
            )
          VALUES
            (
              $1,
              $2,
              $3
            )
          RETURNING
            id,
            user_id,
            post_id,
            body,
            created_at
          `,
          [
            req.user.id,
            postId,
            body
          ]
        );

      const countResult =
        await pool.query(
          `
          SELECT
            COUNT(*)::int AS count
          FROM comments
          WHERE post_id = $1
          `,
          [postId]
        );

      res.status(201).json({
        comment:
          result.rows[0],

        comment_count:
          countResult.rows[0].count
      });

    } catch (error) {

      console.error(
        "ADD COMMENT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to add comment."
      });
    }
  }
);


/* =====================================================
   SHARE POST
===================================================== */

app.post(
  "/api/posts/:id/share",
  requireAuth,
  async (req, res) => {

    try {

      const postId =
        Number(req.params.id);

      if (!Number.isInteger(postId)) {

        return res.status(400).json({
          error:
            "Invalid post ID."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            p.id,
            p.body,
            u.name
          FROM posts p

          JOIN users u
            ON u.id = p.user_id

          WHERE p.id = $1
          `,
          [postId]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          error:
            "Post not found."
        });
      }

      const post =
        result.rows[0];

      const shareUrl =
        `${req.protocol}://${req.get(
          "host"
        )}/?post=${post.id}`;

      const shareText =
        `${post.name} shared on WorldConnect:\n\n${post.body}`;

      res.json({
        post_id:
          post.id,

        share_text:
          shareText,

        url:
          shareUrl
      });

    } catch (error) {

      console.error(
        "SHARE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to share post."
      });
    }
  }
);


/* =====================================================
   DISCOVER USERS
===================================================== */

app.get(
  "/api/users/discover",
  requireAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            u.id,
            u.name,
            u.email,
            u.country,
            u.created_at,

            COUNT(
              DISTINCT followers.follower_id
            )::int AS follower_count,

            COUNT(
              DISTINCT following.following_id
            )::int AS following_count,

            EXISTS (
              SELECT 1
              FROM follows f
              WHERE f.follower_id = $1
                AND f.following_id = u.id
            ) AS following_me

          FROM users u

          LEFT JOIN follows followers
            ON followers.following_id = u.id

          LEFT JOIN follows following
            ON following.follower_id = u.id

          WHERE u.id <> $1

          GROUP BY
            u.id,
            u.name,
            u.email,
            u.country,
            u.created_at

          ORDER BY
            u.created_at DESC

          LIMIT 50
          `,
          [req.user.id]
        );

      res.json({
        users:
          result.rows
      });

    } catch (error) {

      console.error(
        "DISCOVER USERS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to discover users."
      });
    }
  }
);


/* =====================================================
   FOLLOW / UNFOLLOW USER
===================================================== */

app.post(
  "/api/users/:id/follow",
  requireAuth,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const targetId =
        Number(req.params.id);

      if (!Number.isInteger(targetId)) {

        return res.status(400).json({
          error:
            "Invalid user ID."
        });
      }

      if (
        targetId ===
        Number(req.user.id)
      ) {

        return res.status(400).json({
          error:
            "You cannot follow yourself."
        });
      }

      await client.query(
        "BEGIN"
      );

      const userResult =
        await client.query(
          `
          SELECT id
          FROM users
          WHERE id = $1
          `,
          [targetId]
        );

      if (
        userResult.rows.length === 0
      ) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          error:
            "User not found."
        });
      }

      const existing =
        await client.query(
          `
          SELECT 1
          FROM follows
          WHERE follower_id = $1
            AND following_id = $2
          `,
          [
            req.user.id,
            targetId
          ]
        );

      let following;

      if (
        existing.rows.length > 0
      ) {

        await client.query(
          `
          DELETE FROM follows
          WHERE follower_id = $1
            AND following_id = $2
          `,
          [
            req.user.id,
            targetId
          ]
        );

        following = false;

      } else {

        await client.query(
          `
          INSERT INTO follows
            (
              follower_id,
              following_id
            )
          VALUES
            (
              $1,
              $2
            )
          `,
          [
            req.user.id,
            targetId
          ]
        );

        following = true;
      }

      const followersResult =
        await client.query(
          `
          SELECT
            COUNT(*)::int AS count
          FROM follows
          WHERE following_id = $1
          `,
          [targetId]
        );

      const followingResult =
        await client.query(
          `
          SELECT
            COUNT(*)::int AS count
          FROM follows
          WHERE follower_id = $1
          `,
          [targetId]
        );

      await client.query(
        "COMMIT"
      );

      res.json({
        following,

        follower_count:
          followersResult.rows[0].count,

        following_count:
          followingResult.rows[0].count
      });

    } catch (error) {

      await client.query(
        "ROLLBACK"
      );

      console.error(
        "FOLLOW ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to update follow."
      });

    } finally {

      client.release();
    }
  }
);


/* =====================================================
   GET USER PROFILE
===================================================== */

app.get(
  "/api/users/:id",
  requireAuth,
  async (req, res) => {

    try {

      const userId =
        Number(req.params.id);

      if (!Number.isInteger(userId)) {

        return res.status(400).json({
          error:
            "Invalid user ID."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            u.id,
            u.name,
            u.email,
            u.country,
            u.created_at,

            (
              SELECT COUNT(*)
              FROM follows
              WHERE following_id = u.id
            )::int AS follower_count,

            (
              SELECT COUNT(*)
              FROM follows
              WHERE follower_id = u.id
            )::int AS following_count,

            EXISTS (
              SELECT 1
              FROM follows
              WHERE follower_id = $1
                AND following_id = u.id
            ) AS following

          FROM users u

          WHERE u.id = $2
          `,
          [
            req.user.id,
            userId
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          error:
            "User not found."
        });
      }

      res.json({
        user:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "GET USER PROFILE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load profile."
      });
    }
  }
);


/* =====================================================
   STATIC FRONTEND
===================================================== */

app.use(
  express.static(
    path.join(
      __dirname,
      "../public"
    )
  )
);


/* =====================================================
   FRONTEND FALLBACK
   EXPRESS 5 COMPATIBLE
===================================================== */

app.get(
  "/{*splat}",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "../public/index.html"
      )
    );

  }
);


/* =====================================================
   START SERVER
===================================================== */

async function startServer() {

  try {

    await initDb();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `WorldConnect running on port ${PORT}`
        );

      }
    );

  } catch (error) {

    console.error(
      "SERVER START ERROR:",
      error
    );

    process.exit(1);
  }
}


startServer();
