import express from "express";
import cors from "cors";
import helmet from "helmet";
import multer from "multer";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";
import fs from "fs";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import sharp from "sharp";
import { celebrate, Joi, errors as celebrateErrors, Segments } from "celebrate";
import rateLimit from "express-rate-limit";

const app = express();
app.use(express.json());
app.use(helmet());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const MAX_UPLOAD_MB = parseInt(process.env.MAX_UPLOAD_MB || "10");
const PRESETS = (process.env.PRESETS || "FIRE,CLAP,NICE,WOW,LOVE")
  .split(",").map(s=>s.trim()).filter(Boolean);
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "").split(",").filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || CORS_ORIGINS.length === 0 || CORS_ORIGINS.includes(origin)) cb(null, true);
    else cb(new Error("Not allowed by CORS"));
  },
  credentials: false
}));

app.use("/uploads", (req,res,next)=>{
  res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  next();
}, express.static("uploads"));

const db = await open({ filename: "./db.sqlite", driver: sqlite3.Database });
if (fs.existsSync("schema.sql")) await db.exec(fs.readFileSync("./schema.sql","utf8").toString());

const apiLimiter = rateLimit({ windowMs: 15*60*1000, max: 100 });
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 20 });
app.use("/api/", apiLimiter);
app.use("/api/auth", authLimiter);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");
    cb(null, "uploads");
  },
  filename: (req, file, cb) => {
    const ext = path.extname((file.originalname||"").toLowerCase());
    cb(null, uuidv4() + ext);
  }
});
const fileFilter = (req, file, cb) => {
  const ok = ["image/jpeg","image/png","image/webp","image/gif","image/heic","image/heif"].includes(file.mimetype);
  cb(ok ? null : new Error("Invalid file type (image only)"), ok);
};
const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 }
});

function auth(req,res,next){
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if(!token) return res.status(401).json({error:"Unauthorized"});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({error:"Invalid token"}); }
}
const isAdmin = (req)=> !!req.user?.is_admin;

const signupSchema = {
  [Segments.BODY]: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    displayName: Joi.string().min(2).max(40).required()
  })
};
const loginSchema = {
  [Segments.BODY]: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  })
};
const createPostSchema = {
  [Segments.BODY]: Joi.object({
    description: Joi.string().max(1000).allow("").optional()
  })
};
const commentSchema = {
  [Segments.BODY]: Joi.object({
    presetKey: Joi.string().valid(...PRESETS).required()
  })
};
const paginationSchema = {
  [Segments.QUERY]: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(50).default(10)
  })
};

// Auth
app.post("/api/auth/signup", celebrate(signupSchema), async (req,res)=>{
  const {email,password,displayName} = req.body;
  const hash = await bcrypt.hash(password, 10);
  try{
    const r = await db.run(
      "INSERT INTO users (email,password_hash,display_name) VALUES (?,?,?)",
      [email,hash,displayName]
    );
    const user = { id:r.lastID, email, display_name:displayName, is_admin:0 };
    const token = jwt.sign(user, JWT_SECRET, {expiresIn:"30d"});
    res.json({ token, user });
  }catch(e){ res.status(409).json({error:"Email already used"}); }
});

app.post("/api/auth/login", celebrate(loginSchema), async (req,res)=>{
  const {email,password} = req.body;
  const u = await db.get("SELECT * FROM users WHERE email=?", [email]);
  if(!u) return res.status(401).json({error:"Invalid creds"});
  const ok = await bcrypt.compare(password, u.password_hash);
  if(!ok) return res.status(401).json({error:"Invalid creds"});
  const user = { id:u.id, email:u.email, display_name:u.display_name, is_admin:u.is_admin };
  const token = jwt.sign(user, JWT_SECRET, {expiresIn:"30d"});
  res.json({ token, user });
});

// Presets
app.get("/api/presets", (req,res)=> res.json(PRESETS));

// Create post
app.post("/api/posts",
  auth,
  upload.single("image"),
  celebrate(createPostSchema),
  async (req,res)=>{
    if(!req.file) return res.status(400).json({error:"Image required"});
    const original = path.join("uploads", req.file.filename);
    try {
      await sharp(original).rotate().jpeg({ quality: 85, mozjpeg: true }).toFile(original);
    } catch {}
    const { description="" } = req.body;
    const now = Date.now();
    const r = await db.run(
      "INSERT INTO posts (user_id,image_path,description,created_at) VALUES (?,?,?,?)",
      [req.user.id, req.file.filename, description, now]
    );
    res.json({ id:r.lastID });
  }
);

// Feed
app.get("/api/posts", celebrate(paginationSchema), async (req,res)=>{
  const { page, limit } = req.query;
  const offset = (page-1)*limit;
  const rows = await db.all(
    `SELECT p.*, u.display_name
     FROM posts p JOIN users u ON u.id=p.user_id
     ORDER BY p.created_at DESC
     LIMIT ? OFFSET ?`, [limit, offset]
  );
  res.json(rows.map(p=>({
    id: p.id,
    user: { id: p.user_id, displayName: p.display_name },
    imageUrl: `${req.protocol}://${req.get("host")}/uploads/${p.image_path}`,
    description: p.description || "",
    createdAt: p.created_at
  })));
});

// User posts
app.get("/api/users/:id/posts", async (req,res)=>{
  const uid = parseInt(req.params.id);
  const rows = await db.all(
    "SELECT * FROM posts WHERE user_id=? ORDER BY created_at DESC", [uid]
  );
  res.json(rows.map(p=>({
    id: p.id,
    imageUrl: `${req.protocol}://${req.get("host")}/uploads/${p.image_path}`,
    description: p.description || "",
    createdAt: p.created_at
  })));
});

// Post detail
app.get("/api/posts/:id", async (req,res)=>{
  const id = parseInt(req.params.id);
  const p = await db.get(
    `SELECT p.*, u.display_name FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?`, [id]
  );
  if(!p) return res.status(404).json({error:"Not found"});
  const comments = await db.all(
    `SELECT c.*, u.display_name
     FROM comments c JOIN users u ON u.id=c.user_id
     WHERE c.post_id=? ORDER BY c.created_at ASC`, [id]
  );
  res.json({
    id: p.id,
    user: { id: p.user_id, displayName: p.display_name },
    imageUrl: `${req.protocol}://${req.get("host")}/uploads/${p.image_path}`,
    description: p.description || "",
    createdAt: p.created_at,
    comments: comments.map(c=>({
      id:c.id,
      user:{id:c.user_id, displayName:c.display_name},
      presetKey:c.preset_key,
      createdAt:c.created_at
    }))
  });
});

// Add preset comment
app.post("/api/posts/:id/comment",
  auth, celebrate(commentSchema),
  async (req,res)=>{
    const id = parseInt(req.params.id);
    const p = await db.get("SELECT id FROM posts WHERE id=?", [id]);
    if(!p) return res.status(404).json({error:"Post not found"});
    const now = Date.now();
    await db.run(
      "INSERT INTO comments (post_id,user_id,preset_key,created_at) VALUES (?,?,?,?)",
      [id, req.user.id, req.body.presetKey, now]
    );
    res.json({ ok:true });
  }
);

// Delete post (owner or admin)
app.delete("/api/posts/:id", auth, async (req,res)=>{
  const id = parseInt(req.params.id);
  const p = await db.get("SELECT * FROM posts WHERE id=?", [id]);
  if(!p) return res.status(404).json({error:"Not found"});
  if (p.user_id !== req.user.id && !isAdmin(req)) {
    return res.status(403).json({error:"Forbidden"});
  }
  await db.run("DELETE FROM comments WHERE post_id=?", [id]);
  await db.run("DELETE FROM posts WHERE id=?", [id]);
  const img = path.join("uploads", p.image_path);
  if (fs.existsSync(img)) { try { fs.unlinkSync(img); } catch {} }
  res.json({ ok:true });
});

// Validators & errors
app.use(celebrateErrors());
app.use((err, req, res, next)=>{
  if (err?.message?.includes("CORS")) return res.status(403).json({error:"CORS rejected"});
  if (err?.message?.includes("Invalid file type")) return res.status(400).json({error: err.message});
  return res.status(500).json({error:"Server error"});
});

app.listen(PORT, ()=> console.log(`API on http://localhost:${PORT}`));
