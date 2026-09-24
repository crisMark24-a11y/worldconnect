import pg from "pg";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

export async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(80) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      country VARCHAR(80),
      bio TEXT,
      profile_photo_url TEXT,
      cover_photo_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    /*
      These ALTER statements make the update safe
      even if the users table already existed before
      the profile system was added.
    */

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS bio TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS profile_photo_url TEXT;

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS cover_photo_url TEXT;


    CREATE TABLE IF NOT EXISTS posts (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL CHECK (char_length(body) <= 5000),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );


    CREATE TABLE IF NOT EXISTS likes (
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, post_id)
    );


    CREATE TABLE IF NOT EXISTS follows (
      follower_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      following_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (follower_id, following_id),
      CHECK (follower_id <> following_id)
    );


    CREATE TABLE IF NOT EXISTS comments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      body TEXT NOT NULL CHECK (char_length(body) <= 1000),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );


    CREATE TABLE IF NOT EXISTS notifications (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      actor_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(30) NOT NULL,
      post_id BIGINT REFERENCES posts(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );


    CREATE TABLE IF NOT EXISTS conversations (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );


    CREATE TABLE IF NOT EXISTS conversation_members (
      conversation_id BIGINT NOT NULL
        REFERENCES conversations(id)
        ON DELETE CASCADE,

      user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      joined_at TIMESTAMPTZ DEFAULT NOW(),

      last_read_at TIMESTAMPTZ,

      PRIMARY KEY (
        conversation_id,
        user_id
      )
    );


    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,

      conversation_id BIGINT NOT NULL
        REFERENCES conversations(id)
        ON DELETE CASCADE,

      sender_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      body TEXT NOT NULL
        CHECK (char_length(body) <= 5000),

      created_at TIMESTAMPTZ DEFAULT NOW()
    );


    CREATE INDEX IF NOT EXISTS idx_messages_conversation_id_created_at
      ON messages(conversation_id, created_at);


    CREATE INDEX IF NOT EXISTS idx_conversation_members_user_id
      ON conversation_members(user_id);


    CREATE INDEX IF NOT EXISTS idx_notifications_user_id_created_at
      ON notifications(user_id, created_at);


    CREATE INDEX IF NOT EXISTS idx_posts_user_id_created_at
      ON posts(user_id, created_at);


    CREATE INDEX IF NOT EXISTS idx_follows_following_id
      ON follows(following_id);


    CREATE INDEX IF NOT EXISTS idx_follows_follower_id
      ON follows(follower_id);
  `);
}
