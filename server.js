import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import cors from "cors";
import { createServer } from "node:http";
import { Server } from "socket.io";
import crypto from "node:crypto";
import mongoose from "mongoose";
import { createClient } from "redis";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const corsOrigins = (process.env.CORS_ORIGIN ?? "http://localhost:8080,http://127.0.0.1:8080")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const jwtSecret = process.env.JWT_SECRET ?? "dev_insecure_jwt_secret_change_me";
if (!process.env.JWT_SECRET) {
  console.warn("JWT_SECRET is not set. Using an insecure fallback secret for development only.");
}
const cookieName = process.env.AUTH_COOKIE_NAME ?? "pico_auth";
const cookieSecure = process.env.COOKIE_SECURE === "true";
const cookieDomain = process.env.COOKIE_DOMAIN;
const jwtExpiresIn = process.env.JWT_EXPIRES_IN ?? "7d";

const app = express();
app.use(
  cors({
    origin: corsOrigins,
    credentials: true
  })
);
app.use(cookieParser());
app.use(express.json());

const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: corsOrigins,
    credentials: true,
    methods: ["GET", "POST"]
  }
});

const users = new Map();
const rooms = new Map();

const userSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true }
  },
  { timestamps: true }
);

const roomSchema = new mongoose.Schema(
  {
    roomId: { type: String, required: true, unique: true, index: true },
    label: { type: String, required: true },
    roomType: { type: String, enum: ["text", "video"], required: true },
    mode: { type: String, enum: ["duo", "group"], required: true },
    adminId: { type: String, required: true },
    maxUsers: { type: Number, required: true }
  },
  { timestamps: true }
);

const messageSchema = new mongoose.Schema(
  {
    roomId: { type: String, required: true, index: true },
    userId: { type: String, required: true },
    name: { type: String, required: true },
    text: { type: String, required: true },
    ts: { type: Number, required: true }
  },
  { timestamps: true }
);

const UserModel = mongoose.model("User", userSchema);
const RoomModel = mongoose.model("Room", roomSchema);
const MessageModel = mongoose.model("Message", messageSchema);

let mongoReady = false;
let redisReady = false;
let redisClient = null;

async function connectMongo() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.warn("MONGODB_URI not set. Running with in-memory storage.");
    return;
  }
  try {
    await mongoose.connect(uri);
    mongoReady = true;
    console.log("MongoDB connected.");
  } catch (error) {
    console.error("MongoDB connection failed. Falling back to in-memory storage.", error);
    mongoReady = false;
  }
}

async function connectRedis() {
  const redisUrl = process.env.REDIS_URL;
  // console.log("REDIS_URL VALUE =", redisUrl);
  if (!redisUrl) {
    return;
  }
  try {
    redisClient = createClient({ url: redisUrl });
    redisClient.on("error", () => {});
    await redisClient.connect();
    redisReady = true;
    console.log("Redis connected.");
  } catch (error) {
    console.error("Redis connection failed. Continuing without Redis.", error);
    redisReady = false;
    redisClient = null;
  }
}

function issueJwt(userId) {
  return jwt.sign({ sub: userId }, jwtSecret, { expiresIn: jwtExpiresIn });
}

function verifyJwt(token) {
  try {
    const payload = jwt.verify(token, jwtSecret);
    if (!payload || typeof payload !== "object" || typeof payload.sub !== "string") {
      return null;
    }
    return payload.sub;
  } catch {
    return null;
  }
}

function authCookieOptions() {
  const options = {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: "lax",
    path: "/"
  };
  if (cookieDomain) {
    options.domain = cookieDomain;
  }
  return options;
}

function clearAuthCookie(res) {
  const options = authCookieOptions();
  res.clearCookie(cookieName, options);
}

function extractTokenFromRequest(req) {
  const bearer = req.headers.authorization;
  if (bearer && bearer.startsWith("Bearer ")) {
    return bearer.slice("Bearer ".length);
  }
  const cookieToken = req.cookies?.[cookieName];
  if (cookieToken && typeof cookieToken === "string") {
    return cookieToken;
  }
  return null;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) {
    return false;
  }
  const candidate = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(candidate, "hex"));
}

async function findUserByEmail(email) {
  const normalizedEmail = String(email).trim().toLowerCase();
  const inMemoryUser = Array.from(users.values()).find((u) => u.email === normalizedEmail);
  if (inMemoryUser) {
    return inMemoryUser;
  }
  if (!mongoReady) {
    return null;
  }
  const doc = await UserModel.findOne({ email: normalizedEmail }).lean();
  if (!doc) {
    return null;
  }
  users.set(doc.userId, doc);
  return doc;
}

async function findUserById(userId) {
  const inMemoryUser = users.get(userId);
  if (inMemoryUser) {
    return inMemoryUser;
  }
  if (!mongoReady) {
    return null;
  }
  const doc = await UserModel.findOne({ userId }).lean();
  if (!doc) {
    return null;
  }
  users.set(doc.userId, doc);
  return doc;
}

function authUserFromToken(req, res, next) {
  const token = extractTokenFromRequest(req);
  if (!token) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const userId = verifyJwt(token);
  if (!userId) {
    res.status(401).json({ error: "Session expired" });
    return;
  }

  findUserById(userId)
    .then((user) => {
      if (!user) {
        res.status(401).json({ error: "User not found" });
        return;
      }
      req.authUser = user;
      next();
    })
    .catch(() => {
      res.status(500).json({ error: "Auth lookup failed" });
    });
}

function makeRoomId() {
  return crypto.randomBytes(3).toString("hex").toUpperCase();
}

function sanitizeRoom(room) {
  const members = Array.from(room.members).map((userId) => {
    const media = room.memberMedia.get(userId) ?? { micOn: true, camOn: true };
    return {
      userId,
      name: nameOfUser(userId),
      micOn: media.micOn,
      camOn: media.camOn
    };
  });
  return {
    roomId: room.roomId,
    label: room.label,
    roomType: room.roomType,
    mode: room.mode,
    adminId: room.adminId,
    members,
    pending: Array.from(room.pending.keys()).map((userId) => ({
      userId,
      name: nameOfUser(userId)
    })),
    maxUsers: room.maxUsers
  };
}

function emitRoomState(roomId) {
  const room = rooms.get(roomId);
  if (!room) {
    return;
  }
  io.to(`room:${roomId}`).emit("room:state", sanitizeRoom(room));
}

function roomHasCapacity(room) {
  return room.members.size < room.maxUsers;
}

async function hydrateRoom(roomId) {
  const normalizedRoomId = String(roomId).trim().toUpperCase();
  if (rooms.has(normalizedRoomId)) {
    return rooms.get(normalizedRoomId);
  }
  if (!mongoReady) {
    return null;
  }
  const doc = await RoomModel.findOne({ roomId: normalizedRoomId }).lean();
  if (!doc) {
    return null;
  }
  const room = {
    roomId: doc.roomId,
    roomType: doc.roomType,
    mode: doc.mode,
    label: doc.label,
    adminId: doc.adminId,
    members: new Set(),
    pending: new Map(),
    memberMedia: new Map(),
    maxUsers: doc.maxUsers
  };
  rooms.set(normalizedRoomId, room);
  return room;
}

function nameOfUser(userId) {
  return users.get(userId)?.name ?? "User";
}

function parseCookiesFromHeader(headerValue) {
  const out = {};
  if (!headerValue) {
    return out;
  }
  const parts = String(headerValue).split(";");
  for (const part of parts) {
    const [rawKey, ...rawValue] = part.trim().split("=");
    if (!rawKey) {
      continue;
    }
    out[rawKey] = decodeURIComponent(rawValue.join("=") || "");
  }
  return out;
}

function tokenFromSocketHandshake(socket) {
  const authToken = socket.handshake.auth?.token;
  if (authToken && typeof authToken === "string") {
    return authToken;
  }
  const bearerHeader = socket.handshake.headers?.authorization;
  if (typeof bearerHeader === "string" && bearerHeader.startsWith("Bearer ")) {
    return bearerHeader.slice("Bearer ".length);
  }
  const parsedCookies = parseCookiesFromHeader(socket.handshake.headers?.cookie);
  return parsedCookies[cookieName] ?? null;
}

app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body ?? {};
  if (!name || !email || !password) {
    res.status(400).json({ error: "name, email, password are required" });
    return;
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const existing = await findUserByEmail(normalizedEmail);
  if (existing) {
    res.status(409).json({ error: "Email already registered" });
    return;
  }

  const user = {
    userId: crypto.randomUUID(),
    name: String(name).trim(),
    email: normalizedEmail,
    passwordHash: hashPassword(String(password))
  };

  users.set(user.userId, user);
  if (mongoReady) {
    await UserModel.create(user);
  }

  res.status(201).json({ ok: true });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) {
    res.status(400).json({ error: "email and password are required" });
    return;
  }

  const user = await findUserByEmail(email);
  if (!user || !verifyPassword(String(password), user.passwordHash)) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const token = issueJwt(user.userId);
  res.cookie(cookieName, token, authCookieOptions());
  res.json({
    token,
    user: { userId: user.userId, name: user.name, email: user.email }
  });
});

app.post("/api/logout", authUserFromToken, (req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.get("/api/me", authUserFromToken, (req, res) => {
  const { userId, name, email } = req.authUser;
  res.json({ user: { userId, name, email } });
});

app.post("/api/rooms", authUserFromToken, async (req, res) => {
  const { roomType, mode, label } = req.body ?? {};
  if (!["text", "video"].includes(roomType)) {
    res.status(400).json({ error: "roomType must be text or video" });
    return;
  }
  if (!["duo", "group"].includes(mode)) {
    res.status(400).json({ error: "mode must be duo or group" });
    return;
  }

  let roomId = makeRoomId();
  while (rooms.has(roomId)) {
    roomId = makeRoomId();
  }

  const room = {
    roomId,
    roomType,
    mode,
    label: String(label ?? "").trim() || `${roomType}-${mode}-${roomId}`,
    adminId: req.authUser.userId,
    members: new Set([req.authUser.userId]),
    pending: new Map(),
    memberMedia: new Map([[req.authUser.userId, { micOn: true, camOn: true }]]),
    maxUsers: mode === "duo" ? 2 : 20
  };

  rooms.set(roomId, room);
  if (mongoReady) {
    await RoomModel.updateOne(
      { roomId },
      {
        roomId,
        roomType,
        mode,
        label: room.label,
        adminId: room.adminId,
        maxUsers: room.maxUsers
      },
      { upsert: true }
    );
  }

  res.status(201).json({ room: sanitizeRoom(room) });
});

app.get("/api/rooms/:roomId", authUserFromToken, async (req, res) => {
  const room = await hydrateRoom(req.params.roomId);
  if (!room) {
    res.status(404).json({ error: "Room not found" });
    return;
  }
  res.json({ room: sanitizeRoom(room) });
});

app.get("/api/rooms/:roomId/messages", authUserFromToken, async (req, res) => {
  const roomId = String(req.params.roomId).trim().toUpperCase();
  const limit = Math.max(1, Math.min(60, Number(req.query.limit) || 30));
  const beforeTsRaw = Number(req.query.beforeTs);
  const beforeTs = Number.isFinite(beforeTsRaw) && beforeTsRaw > 0 ? beforeTsRaw : null;

  if (!mongoReady && !redisReady) {
    res.json({ messages: [], hasMore: false });
    return;
  }

  if (redisReady && redisClient) {
    const cacheKey = `room:${roomId}:messages`;
    const cached = await redisClient.lRange(cacheKey, 0, 400);
    if (cached.length > 0) {
      let parsed = cached
        .map((item) => {
          try {
            return JSON.parse(item);
          } catch {
            return null;
          }
        })
        .filter(Boolean);
      if (beforeTs) {
        parsed = parsed.filter((m) => m.ts < beforeTs);
      }
      parsed.sort((a, b) => a.ts - b.ts);
      const sliced = parsed.slice(Math.max(parsed.length - limit, 0));
      const hasMore = parsed.length > sliced.length;
      res.json({ messages: sliced, hasMore });
      return;
    }
  }

  if (!mongoReady) {
    res.json({ messages: [], hasMore: false });
    return;
  }

  const query = beforeTs ? { roomId, ts: { $lt: beforeTs } } : { roomId };
  const rawMessages = await MessageModel.find(query).sort({ ts: -1 }).limit(limit + 1).lean();
  const hasMore = rawMessages.length > limit;
  const messages = rawMessages.slice(0, limit).reverse();
  res.json({ messages, hasMore });
});

io.on("connection", async (socket) => {
  const token = tokenFromSocketHandshake(socket);
  const userId = verifyJwt(token);
  if (!userId) {
    socket.emit("auth:error", "Unauthorized socket session");
    socket.disconnect(true);
    return;
  }

  const user = await findUserById(userId);
  if (!user) {
    socket.emit("auth:error", "User not found");
    socket.disconnect(true);
    return;
  }

  socket.data.userId = userId;
  socket.join(`user:${userId}`);

  socket.on("room:request-join", async ({ roomId }) => {
    const normalizedRoomId = String(roomId ?? "").trim().toUpperCase();
    const room = await hydrateRoom(normalizedRoomId);
    if (!room) {
      socket.emit("room:error", "Room not found");
      return;
    }

    socket.join(`room:${normalizedRoomId}`);
    if (room.members.has(userId)) {
      if (!room.memberMedia.has(userId)) {
        room.memberMedia.set(userId, { micOn: true, camOn: true });
      }
      socket.emit("room:joined", sanitizeRoom(room));
      emitRoomState(normalizedRoomId);
      return;
    }

    if (!roomHasCapacity(room)) {
      socket.emit("room:error", "Room is full");
      return;
    }

    if (room.mode === "group" && userId !== room.adminId) {
      room.pending.set(userId, socket.id);
      io.to(`user:${room.adminId}`).emit("room:join-request", {
        roomId: normalizedRoomId,
        userId,
        name: nameOfUser(userId)
      });
      socket.emit("room:pending", {
        roomId: normalizedRoomId,
        message: "Request sent to admin"
      });
      emitRoomState(normalizedRoomId);
      return;
    }

    room.members.add(userId);
    room.memberMedia.set(userId, room.memberMedia.get(userId) ?? { micOn: true, camOn: true });
    socket.to(`room:${normalizedRoomId}`).emit("room:user-joined", {
      roomId: normalizedRoomId,
      userId,
      name: nameOfUser(userId)
    });
    socket.emit("room:joined", sanitizeRoom(room));
    emitRoomState(normalizedRoomId);
  });

  socket.on("room:approve", ({ roomId, targetUserId, allow }) => {
    const normalizedRoomId = String(roomId ?? "").trim().toUpperCase();
    const room = rooms.get(normalizedRoomId);
    if (!room || room.adminId !== userId) {
      return;
    }

    const pendingSocketId = room.pending.get(targetUserId);
    if (!pendingSocketId) {
      return;
    }

    room.pending.delete(targetUserId);
    if (!allow) {
      io.to(pendingSocketId).emit("room:rejected", { roomId: normalizedRoomId });
      emitRoomState(normalizedRoomId);
      return;
    }

    if (!roomHasCapacity(room)) {
      io.to(pendingSocketId).emit("room:error", "Room is full");
      emitRoomState(normalizedRoomId);
      return;
    }

    room.members.add(targetUserId);
    room.memberMedia.set(targetUserId, room.memberMedia.get(targetUserId) ?? { micOn: true, camOn: true });
    const targetSocket = io.sockets.sockets.get(pendingSocketId);
    targetSocket?.join(`room:${normalizedRoomId}`);
    io.to(`user:${targetUserId}`).emit("room:joined", sanitizeRoom(room));
    io.to(`room:${normalizedRoomId}`).emit("room:user-joined", {
      roomId: normalizedRoomId,
      userId: targetUserId,
      name: nameOfUser(targetUserId)
    });
    emitRoomState(normalizedRoomId);
  });

  socket.on("room:leave", ({ roomId }) => {
    const normalizedRoomId = String(roomId ?? "").trim().toUpperCase();
    const room = rooms.get(normalizedRoomId);
    if (!room) {
      return;
    }

    room.pending.delete(userId);
    room.members.delete(userId);
    room.memberMedia.delete(userId);
    socket.leave(`room:${normalizedRoomId}`);
    socket.to(`room:${normalizedRoomId}`).emit("room:user-left", { userId, roomId: normalizedRoomId });

    if (room.members.size === 0) {
      rooms.delete(normalizedRoomId);
      if (mongoReady) {
        RoomModel.deleteOne({ roomId: normalizedRoomId }).catch(() => {});
      }
      return;
    }

    emitRoomState(normalizedRoomId);
  });

  socket.on("room:message", ({ roomId, text }) => {
    const normalizedRoomId = String(roomId ?? "").trim().toUpperCase();
    const room = rooms.get(normalizedRoomId);
    if (!room || !room.members.has(userId)) {
      return;
    }
    const message = {
      roomId: normalizedRoomId,
      userId,
      name: nameOfUser(userId),
      text: String(text ?? "").slice(0, 500),
      ts: Date.now()
    };
    io.to(`room:${normalizedRoomId}`).emit("room:message", message);
    if (redisReady && redisClient) {
      const cacheKey = `room:${normalizedRoomId}:messages`;
      redisClient
        .rPush(cacheKey, JSON.stringify(message))
        .then(() => redisClient.lTrim(cacheKey, -300, -1))
        .catch(() => {});
    }
    if (mongoReady) {
      MessageModel.create(message).catch(() => {});
    }
  });

  socket.on("room:media", ({ roomId, micOn, camOn }) => {
    const normalizedRoomId = String(roomId ?? "").trim().toUpperCase();
    const room = rooms.get(normalizedRoomId);
    if (!room || !room.members.has(userId)) {
      return;
    }
    const current = room.memberMedia.get(userId) ?? { micOn: true, camOn: true };
    const next = {
      micOn: typeof micOn === "boolean" ? micOn : current.micOn,
      camOn: typeof camOn === "boolean" ? camOn : current.camOn
    };
    room.memberMedia.set(userId, next);
    io.to(`room:${normalizedRoomId}`).emit("room:member-media", {
      roomId: normalizedRoomId,
      userId,
      ...next
    });
    emitRoomState(normalizedRoomId);
  });

  socket.on("room:signal", ({ roomId, to, signal }) => {
    const normalizedRoomId = String(roomId ?? "").trim().toUpperCase();
    const room = rooms.get(normalizedRoomId);
    if (!room || !room.members.has(userId) || !to) {
      return;
    }
    io.to(`user:${to}`).emit("room:signal", { from: userId, roomId: normalizedRoomId, signal });
  });

  socket.on("room:sync-peers", ({ roomId }) => {
    const normalizedRoomId = String(roomId ?? "").trim().toUpperCase();
    const room = rooms.get(normalizedRoomId);
    if (!room || !room.members.has(userId)) {
      return;
    }
    socket.emit("room:peers", {
      roomId: normalizedRoomId,
      peers: Array.from(room.members).filter((id) => id !== userId)
    });
  });

  socket.on("disconnect", () => {
    for (const [roomId, room] of rooms.entries()) {
      if (!room.members.has(userId) && !room.pending.has(userId)) {
        continue;
      }
      room.pending.delete(userId);
      room.members.delete(userId);
      room.memberMedia.delete(userId);
      socket.to(`room:${roomId}`).emit("room:user-left", { userId, roomId });
      if (room.members.size === 0) {
        rooms.delete(roomId);
        if (mongoReady) {
          RoomModel.deleteOne({ roomId }).catch(() => {});
        }
        continue;
      }
      emitRoomState(roomId);
    }
  });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, mongo: mongoReady, redis: redisReady });
});

const distPath = path.resolve(__dirname, "../dist");
app.use(express.static(distPath));
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

const PORT = Number(process.env.PORT) || 3000;
await connectMongo();
await connectRedis();
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
