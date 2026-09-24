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
  process.env.JWT_SECRET ||
  "worldconnect-development-secret";

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
   PROFILE DATABASE MIGRATION

   Automatically adds profile fields to existing
   WorldConnect users table.
===================================================== */

async function ensureProfileColumns() {
  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS bio TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS profile_photo_url TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS cover_photo_url TEXT;
  `);

  console.log(
    "Profile database fields verified."
  );
}


/* =====================================================
   NOTIFICATION HELPER
===================================================== */

async function createNotification({
  userId,
  actorId,
  type,
  postId = null,
  message
}) {
  if (
    !userId ||
    !actorId ||
    Number(userId) === Number(actorId)
  ) {
    return;
  }

  await pool.query(
    `
    INSERT INTO notifications
      (
        user_id,
        actor_id,
        type,
        post_id,
        message
      )
    VALUES
      (
        $1,
        $2,
        $3,
        $4,
        $5
      )
    `,
    [
      userId,
      actorId,
      type,
      postId,
      message
    ]
  );
}


/* =====================================================
   HEALTH
===================================================== */

app.get(
  "/api/health",
  async (req, res) => {
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
        error:
          "Database connection failed."
      });
    }
  }
);


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
            bio,
            profile_photo_url,
            cover_photo_url,
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
            bio,
            profile_photo_url,
            cover_photo_url,
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
   CURRENT USER / MY PROFILE
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
            u.id,
            u.name,
            u.email,
            u.country,
            u.bio,
            u.profile_photo_url,
            u.cover_photo_url,
            u.created_at,

            (
              SELECT COUNT(*)
              FROM posts
              WHERE user_id = u.id
            )::int AS post_count,

            (
              SELECT COUNT(*)
              FROM follows
              WHERE following_id = u.id
            )::int AS follower_count,

            (
              SELECT COUNT(*)
              FROM follows
              WHERE follower_id = u.id
            )::int AS following_count

          FROM users u

          WHERE u.id = $1
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
   UPDATE MY PROFILE
===================================================== */

app.put(
  "/api/users/me",
  requireAuth,
  async (req, res) => {
    try {
      const {
        name,
        country,
        bio,
        profile_photo_url,
        cover_photo_url
      } = req.body;

      const cleanName =
        String(name ?? "").trim();

      const cleanCountry =
        String(country ?? "").trim();

      const cleanBio =
        String(bio ?? "").trim();

      const cleanProfilePhoto =
        String(profile_photo_url ?? "").trim();

      const cleanCoverPhoto =
        String(cover_photo_url ?? "").trim();

      if (!cleanName) {
        return res.status(400).json({
          error:
            "Name cannot be empty."
        });
      }

      if (cleanName.length > 80) {
        return res.status(400).json({
          error:
            "Name is too long."
        });
      }

      if (cleanCountry.length > 80) {
        return res.status(400).json({
          error:
            "Country is too long."
        });
      }

      if (cleanBio.length > 500) {
        return res.status(400).json({
          error:
            "Bio is too long. Maximum is 500 characters."
        });
      }

      if (cleanProfilePhoto.length > 2000) {
        return res.status(400).json({
          error:
            "Profile photo URL is too long."
        });
      }

      if (cleanCoverPhoto.length > 2000) {
        return res.status(400).json({
          error:
            "Cover photo URL is too long."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE users

          SET
            name = $1,
            country = $2,
            bio = $3,
            profile_photo_url = $4,
            cover_photo_url = $5

          WHERE id = $6

          RETURNING
            id,
            name,
            email,
            country,
            bio,
            profile_photo_url,
            cover_photo_url,
            created_at
          `,
          [
            cleanName,
            cleanCountry || null,
            cleanBio || null,
            cleanProfilePhoto || null,
            cleanCoverPhoto || null,
            req.user.id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error:
            "User not found."
        });
      }

      res.json({
        ok: true,
        user:
          result.rows[0]
      });

    } catch (error) {
      console.error(
        "UPDATE PROFILE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to update profile."
      });
    }
  }
);


/* =====================================================
   WORLD FEED
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
            u.profile_photo_url,

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
            u.country,
            u.profile_photo_url

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

      if (postResult.rows.length === 0) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          error:
            "Post not found."
        });
      }

      const postOwnerId =
        postResult.rows[0].user_id;

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

      if (existing.rows.length > 0) {

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

        if (
          Number(postOwnerId) !==
          Number(req.user.id)
        ) {
          const actorResult =
            await client.query(
              `
              SELECT name
              FROM users
              WHERE id = $1
              `,
              [req.user.id]
            );

          const actorName =
            actorResult.rows[0]?.name ||
            "Someone";

          await client.query(
            `
            INSERT INTO notifications
              (
                user_id,
                actor_id,
                type,
                post_id,
                message
              )
            VALUES
              (
                $1,
                $2,
                'like',
                $3,
                $4
              )
            `,
            [
              postOwnerId,
              req.user.id,
              postId,
              `${actorName} liked your post.`
            ]
          );
        }
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

      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

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
            u.country,
            u.profile_photo_url

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
          SELECT
            id,
            user_id
          FROM posts
          WHERE id = $1
          `,
          [postId]
        );

      if (post.rows.length === 0) {
        return res.status(404).json({
          error:
            "Post not found."
        });
      }

      const postOwnerId =
        post.rows[0].user_id;

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

      if (
        Number(postOwnerId) !==
        Number(req.user.id)
      ) {
        const actorResult =
          await pool.query(
            `
            SELECT name
            FROM users
            WHERE id = $1
            `,
            [req.user.id]
          );

        const actorName =
          actorResult.rows[0]?.name ||
          "Someone";

        await pool.query(
          `
          INSERT INTO notifications
            (
              user_id,
              actor_id,
              type,
              post_id,
              message
            )
          VALUES
            (
              $1,
              $2,
              'comment',
              $3,
              $4
            )
          `,
          [
            postOwnerId,
            req.user.id,
            postId,
            `${actorName} commented on your post.`
          ]
        );
      }

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

      if (result.rows.length === 0) {
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
            u.bio,
            u.profile_photo_url,
            u.cover_photo_url,
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
            u.bio,
            u.profile_photo_url,
            u.cover_photo_url,
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
          SELECT
            id,
            name
          FROM users
          WHERE id = $1
          `,
          [targetId]
        );

      if (userResult.rows.length === 0) {
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

      if (existing.rows.length > 0) {

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

        const actorResult =
          await client.query(
            `
            SELECT name
            FROM users
            WHERE id = $1
            `,
            [req.user.id]
          );

        const actorName =
          actorResult.rows[0]?.name ||
          "Someone";

        await client.query(
          `
          INSERT INTO notifications
            (
              user_id,
              actor_id,
              type,
              message
            )
          VALUES
            (
              $1,
              $2,
              'follow',
              $3
            )
          `,
          [
            targetId,
            req.user.id,
            `${actorName} started following you.`
          ]
        );
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

      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

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
   USER PROFILE
   Includes profile information + posts
===================================================== */

app.get(
  "/api/users/:id",
  requireAuth,
  async (req, res) => {
    try {
      const userId =
        Number(req.params.id);

      if (
        !Number.isInteger(userId) ||
        userId <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid user ID."
        });
      }

      const userResult =
        await pool.query(
          `
          SELECT
            u.id,
            u.name,
            u.email,
            u.country,
            u.bio,
            u.profile_photo_url,
            u.cover_photo_url,
            u.created_at,

            (
              SELECT COUNT(*)
              FROM posts
              WHERE user_id = u.id
            )::int AS post_count,

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

      if (userResult.rows.length === 0) {
        return res.status(404).json({
          error:
            "User not found."
        });
      }

      const postsResult =
        await pool.query(
          `
          SELECT
            p.id,
            p.body,
            p.created_at,

            u.id AS user_id,
            u.name,
            u.country,
            u.profile_photo_url,

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

          WHERE p.user_id = $2

          GROUP BY
            p.id,
            p.body,
            p.created_at,
            u.id,
            u.name,
            u.country,
            u.profile_photo_url

          ORDER BY
            p.created_at DESC

          LIMIT 100
          `,
          [
            req.user.id,
            userId
          ]
        );

      res.json({
        user:
          userResult.rows[0],

        posts:
          postsResult.rows
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
   NOTIFICATIONS
===================================================== */

app.get(
  "/api/notifications",
  requireAuth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            n.id,
            n.type,
            n.message,
            n.post_id,
            n.is_read,
            n.created_at,

            a.id AS actor_id,
            a.name AS actor_name,
            a.country AS actor_country,
            a.profile_photo_url AS actor_profile_photo

          FROM notifications n

          LEFT JOIN users a
            ON a.id = n.actor_id

          WHERE n.user_id = $1

          ORDER BY
            n.created_at DESC

          LIMIT 100
          `,
          [req.user.id]
        );

      const unreadResult =
        await pool.query(
          `
          SELECT
            COUNT(*)::int AS count

          FROM notifications

          WHERE user_id = $1
            AND is_read = FALSE
          `,
          [req.user.id]
        );

      res.json({
        notifications:
          result.rows,

        unread_count:
          unreadResult.rows[0].count
      });

    } catch (error) {
      console.error(
        "GET NOTIFICATIONS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load notifications."
      });
    }
  }
);


/* =====================================================
   MARK ONE NOTIFICATION AS READ
===================================================== */

app.post(
  "/api/notifications/:id/read",
  requireAuth,
  async (req, res) => {
    try {
      const notificationId =
        Number(req.params.id);

      if (
        !Number.isInteger(
          notificationId
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid notification ID."
        });
      }

      await pool.query(
        `
        UPDATE notifications

        SET is_read = TRUE

        WHERE id = $1
          AND user_id = $2
        `,
        [
          notificationId,
          req.user.id
        ]
      );

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        "MARK NOTIFICATION READ ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to mark notification as read."
      });
    }
  }
);


/* =====================================================
   MARK ALL NOTIFICATIONS AS READ
===================================================== */

app.post(
  "/api/notifications/read-all",
  requireAuth,
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE notifications

        SET is_read = TRUE

        WHERE user_id = $1
        `,
        [req.user.id]
      );

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        "MARK ALL NOTIFICATIONS READ ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to mark notifications as read."
      });
    }
  }
);


/* =====================================================
   CONVERSE
   CREATE / GET PRIVATE CONVERSATION
===================================================== */

app.post(
  "/api/conversations",
  requireAuth,
  async (req, res) => {

    const client =
      await pool.connect();

    try {
      const targetUserId =
        Number(req.body.user_id);

      if (!Number.isInteger(targetUserId)) {
        return res.status(400).json({
          error:
            "Invalid user ID."
        });
      }

      if (
        targetUserId ===
        Number(req.user.id)
      ) {
        return res.status(400).json({
          error:
            "You cannot start a conversation with yourself."
        });
      }

      await client.query(
        "BEGIN"
      );

      const targetResult =
        await client.query(
          `
          SELECT
            id,
            name,
            email,
            country,
            bio,
            profile_photo_url
          FROM users
          WHERE id = $1
          `,
          [targetUserId]
        );

      if (targetResult.rows.length === 0) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          error:
            "User not found."
        });
      }

      const existingResult =
        await client.query(
          `
          SELECT
            c.id
          FROM conversations c

          JOIN conversation_members cm
            ON cm.conversation_id = c.id

          WHERE cm.user_id IN ($1, $2)

          GROUP BY c.id

          HAVING COUNT(DISTINCT cm.user_id) = 2
             AND COUNT(*) = 2

          ORDER BY c.id ASC

          LIMIT 1
          `,
          [
            req.user.id,
            targetUserId
          ]
        );

      let conversationId;

      if (existingResult.rows.length > 0) {

        conversationId =
          existingResult.rows[0].id;

      } else {

        const conversationResult =
          await client.query(
            `
            INSERT INTO conversations
              DEFAULT VALUES

            RETURNING id
            `
          );

        conversationId =
          conversationResult.rows[0].id;

        await client.query(
          `
          INSERT INTO conversation_members
            (
              conversation_id,
              user_id
            )
          VALUES
            ($1, $2),
            ($1, $3)
          `,
          [
            conversationId,
            req.user.id,
            targetUserId
          ]
        );
      }

      await client.query(
        "COMMIT"
      );

      const targetUser =
        targetResult.rows[0];

      res.status(200).json({
        conversation: {
          id: Number(conversationId),

          other_user_id:
            Number(targetUser.id),

          other_user_name:
            targetUser.name,

          other_user_email:
            targetUser.email,

          other_user_country:
            targetUser.country,

          other_user_bio:
            targetUser.bio,

          other_user_profile_photo:
            targetUser.profile_photo_url
        },

        user: targetUser
      });

    } catch (error) {

      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      console.error(
        "CREATE CONVERSATION ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to create conversation."
      });

    } finally {
      client.release();
    }
  }
);


/* =====================================================
   CONVERSE
   GET MY CONVERSATIONS
===================================================== */

app.get(
  "/api/conversations",
  requireAuth,
  async (req, res) => {
    try {

      const result =
        await pool.query(
          `
          SELECT
            c.id AS id,

            u.id AS other_user_id,
            u.name AS other_user_name,
            u.email AS other_user_email,
            u.country AS other_user_country,
            u.profile_photo_url AS other_user_profile_photo,

            lm.body AS last_message,
            lm.created_at AS last_message_at,

            COALESCE(
              unread.unread_count,
              0
            )::int AS unread_count

          FROM conversations c

          JOIN conversation_members my_member
            ON my_member.conversation_id = c.id
           AND my_member.user_id = $1

          JOIN conversation_members other_member
            ON other_member.conversation_id = c.id
           AND other_member.user_id <> $1

          JOIN users u
            ON u.id = other_member.user_id

          LEFT JOIN LATERAL (
            SELECT
              m.body,
              m.created_at
            FROM messages m
            WHERE m.conversation_id = c.id
            ORDER BY m.created_at DESC
            LIMIT 1
          ) lm ON TRUE

          LEFT JOIN LATERAL (
            SELECT
              COUNT(*) AS unread_count
            FROM messages m
            WHERE m.conversation_id = c.id
              AND m.sender_id <> $1
              AND (
                my_member.last_read_at IS NULL
                OR m.created_at > my_member.last_read_at
              )
          ) unread ON TRUE

          ORDER BY
            COALESCE(
              lm.created_at,
              c.created_at
            ) DESC

          LIMIT 100
          `,
          [req.user.id]
        );

      const conversations =
        result.rows.map(
          row => ({
            id: Number(row.id),

            other_user_id:
              Number(row.other_user_id),

            other_user_name:
              row.other_user_name ||
              "User",

            other_user_email:
              row.other_user_email ||
              "",

            other_user_country:
              row.other_user_country ||
              "World",

            other_user_profile_photo:
              row.other_user_profile_photo ||
              "",

            last_message:
              row.last_message ||
              "",

            last_message_at:
              row.last_message_at ||
              null,

            unread_count:
              Number(row.unread_count || 0)
          })
        );

      res.json({
        conversations
      });

    } catch (error) {

      console.error(
        "GET CONVERSATIONS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load conversations."
      });
    }
  }
);


/* =====================================================
   CONVERSE
   GET MESSAGE HISTORY
===================================================== */

app.get(
  "/api/conversations/:id/messages",
  requireAuth,
  async (req, res) => {

    try {

      const conversationId =
        Number(req.params.id);

      if (
        !Number.isInteger(
          conversationId
        ) ||
        conversationId <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid conversation ID."
        });
      }

      const access =
        await pool.query(
          `
          SELECT
            conversation_id,
            user_id
          FROM conversation_members
          WHERE conversation_id = $1
            AND user_id = $2
          `,
          [
            conversationId,
            req.user.id
          ]
        );

      if (access.rows.length === 0) {

        return res.status(404).json({
          error:
            "Conversation not found."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            m.id,
            m.conversation_id,
            m.sender_id,
            m.body,
            m.created_at,

            u.name AS sender_name,
            u.country AS sender_country,
            u.profile_photo_url AS sender_profile_photo

          FROM messages m

          JOIN users u
            ON u.id = m.sender_id

          WHERE m.conversation_id = $1

          ORDER BY
            m.created_at ASC

          LIMIT 500
          `,
          [conversationId]
        );

      res.json({
        conversation_id:
          conversationId,

        messages:
          result.rows
      });

    } catch (error) {

      console.error(
        "GET MESSAGES ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load messages."
      });
    }
  }
);


/* =====================================================
   CONVERSE
   SEND MESSAGE
===================================================== */

app.post(
  "/api/conversations/:id/messages",
  requireAuth,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const conversationId =
        Number(req.params.id);

      const body =
        String(
          req.body.body || ""
        ).trim();

      if (
        !Number.isInteger(
          conversationId
        ) ||
        conversationId <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid conversation ID."
        });
      }

      if (!body) {
        return res.status(400).json({
          error:
            "Message cannot be empty."
        });
      }

      if (body.length > 5000) {
        return res.status(400).json({
          error:
            "Message is too long."
        });
      }

      await client.query(
        "BEGIN"
      );

      const memberResult =
        await client.query(
          `
          SELECT
            cm.user_id
          FROM conversation_members cm

          WHERE cm.conversation_id = $1
          `,
          [conversationId]
        );

      if (
        memberResult.rows.length !== 2
      ) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          error:
            "Conversation not found."
        });
      }

      const isMember =
        memberResult.rows.some(
          row =>
            Number(row.user_id) ===
            Number(req.user.id)
        );

      if (!isMember) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(403).json({
          error:
            "You do not have access to this conversation."
        });
      }

      const result =
        await client.query(
          `
          INSERT INTO messages
            (
              conversation_id,
              sender_id,
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
            conversation_id,
            sender_id,
            body,
            created_at
          `,
          [
            conversationId,
            req.user.id,
            body
          ]
        );

      const receiver =
        memberResult.rows.find(
          row =>
            Number(row.user_id) !==
            Number(req.user.id)
        );

      if (receiver) {

        const actorResult =
          await client.query(
            `
            SELECT
              name
            FROM users
            WHERE id = $1
            `,
            [req.user.id]
          );

        const actorName =
          actorResult.rows[0]?.name ||
          "Someone";

        await client.query(
          `
          INSERT INTO notifications
            (
              user_id,
              actor_id,
              type,
              message
            )
          VALUES
            (
              $1,
              $2,
              'message',
              $3
            )
          `,
          [
            receiver.user_id,
            req.user.id,
            `${actorName} sent you a message.`
          ]
        );
      }

      await client.query(
        `
        UPDATE conversation_members

        SET last_read_at = NOW()

        WHERE conversation_id = $1
          AND user_id = $2
        `,
        [
          conversationId,
          req.user.id
        ]
      );

      await client.query(
        "COMMIT"
      );

      res.status(201).json({
        message:
          result.rows[0]
      });

    } catch (error) {

      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      console.error(
        "SEND MESSAGE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to send message."
      });

    } finally {
      client.release();
    }
  }
);


/* =====================================================
   CONVERSE
   MARK CONVERSATION AS READ
===================================================== */

app.post(
  "/api/conversations/:id/read",
  requireAuth,
  async (req, res) => {

    try {

      const conversationId =
        Number(req.params.id);

      if (
        !Number.isInteger(
          conversationId
        ) ||
        conversationId <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid conversation ID."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE conversation_members

          SET last_read_at = NOW()

          WHERE conversation_id = $1
            AND user_id = $2

          RETURNING
            conversation_id,
            user_id,
            last_read_at
          `,
          [
            conversationId,
            req.user.id
          ]
        );

      if (result.rows.length === 0) {

        return res.status(404).json({
          error:
            "Conversation not found."
        });
      }

      res.json({
        ok: true,

        conversation:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "MARK CONVERSATION READ ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to mark conversation as read."
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

    await ensureProfileColumns();

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
