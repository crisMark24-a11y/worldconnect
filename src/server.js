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
if (!JWT_SECRET) throw new Error("JWT_SECRET is required");

function tokenFor(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}
function auth(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "Login required" });
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: "Invalid or expired token" }); }
}

app.get("/api/health", (_, res) => res.json({ ok: true, service: "WorldConnect API" }));

app.post("/api/auth/register", async (req,res) => {
  try {
    const { name, email, password, country } = req.body;
    if (!name || !email || !password) return res.status(400).json({error:"Name, email and password are required"});
    if (password.length < 8) return res.status(400).json({error:"Password must be at least 8 characters"});
    const hash = await bcrypt.hash(password, 12);
    const q = await pool.query(
      "INSERT INTO users(name,email,password_hash,country) VALUES($1,$2,$3,$4) RETURNING id,name,email,country,created_at",
      [name.trim(), email.toLowerCase().trim(), hash, country || null]
    );
    const user = q.rows[0];
    res.status(201).json({ user, token: tokenFor(user) });
  } catch(e) {
    if (e.code === "23505") return res.status(409).json({error:"Email is already registered"});
    console.error(e); res.status(500).json({error:"Server error"});
  }
});

app.post("/api/auth/login", async (req,res) => {
  try {
    const { email, password } = req.body;
    const q = await pool.query("SELECT * FROM users WHERE email=$1", [String(email||"").toLowerCase().trim()]);
    const user = q.rows[0];
    if (!user || !(await bcrypt.compare(password || "", user.password_hash))) return res.status(401).json({error:"Invalid email or password"});
    delete user.password_hash;
    res.json({ user, token: tokenFor(user) });
  } catch(e) { console.error(e); res.status(500).json({error:"Server error"}); }
});

app.get("/api/me", auth, async (req,res) => {
  const q = await pool.query("SELECT id,name,email,country,created_at FROM users WHERE id=$1",[req.user.id]);
  res.json(q.rows[0] || null);
});

app.get("/api/posts", async (_,res) => {
  const q = await pool.query(`
    SELECT p.id,p.body,p.created_at,u.id AS user_id,u.name,u.country,
      (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id)::int AS likes,
      (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id)::int AS comments
    FROM posts p JOIN users u ON u.id=p.user_id
    ORDER BY p.created_at DESC LIMIT 50`);
  res.json(q.rows);
});

app.post("/api/posts", auth, async (req,res) => {
  const body = String(req.body.body||"").trim();
  if (!body) return res.status(400).json({error:"Post cannot be empty"});
  if (body.length > 5000) return res.status(400).json({error:"Post is too long"});
  const q = await pool.query(
    "INSERT INTO posts(user_id,body) VALUES($1,$2) RETURNING id,body,created_at",
    [req.user.id, body]
  );
  res.status(201).json(q.rows[0]);
});

app.post("/api/posts/:id/like", auth, async (req,res) => {
  const id = Number(req.params.id);
  await pool.query(`
    INSERT INTO likes(user_id,post_id) VALUES($1,$2)
    ON CONFLICT (user_id,post_id) DO NOTHING`, [req.user.id,id]);
  const q = await pool.query("SELECT COUNT(*)::int AS likes FROM likes WHERE post_id=$1",[id]);
  res.json(q.rows[0]);
});

app.post("/api/posts/:id/comment", auth, async (req,res) => {
  const body = String(req.body.body||"").trim();
  if (!body || body.length > 1000) return res.status(400).json({error:"Comment must be 1-1000 characters"});
  const q = await pool.query(
    "INSERT INTO comments(user_id,post_id,body) VALUES($1,$2,$3) RETURNING id,body,created_at",
    [req.user.id,Number(req.params.id),body]);
  res.status(201).json(q.rows[0]);
});

app.post("/api/users/:id/follow", auth, async (req,res) => {
  const id = Number(req.params.id);
  if (id === Number(req.user.id)) return res.status(400).json({error:"You cannot follow yourself"});
  await pool.query(`INSERT INTO follows(follower_id,following_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,[req.user.id,id]);
  res.json({following:true});
});

const port = process.env.PORT || 3000;
initDb().then(()=>app.listen(port,()=>console.log(`WorldConnect running on port ${port}`)))
  .catch(err=>{ console.error("Database initialization failed:",err); process.exit(1); });
