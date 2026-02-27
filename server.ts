import express from "express";
import { createServer as createViteServer } from "vite";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key-for-dev";

app.use(cors());
app.use(express.json());

// Initialize SQLite Database (Mocking MongoDB for this environment)
const db = new Database("smartpay.db");

// Database Schema Setup
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    balance REAL DEFAULT 0.0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT NOT NULL, -- 'income', 'expense', 'transfer', 'bill'
    amount REAL NOT NULL,
    category TEXT,
    description TEXT,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS bills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    biller TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    due_date DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// Auth Middleware
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- API Routes ---

// Auth
app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    const info = stmt.run(name, email, hashedPassword);
    
    // Create wallet
    db.prepare("INSERT INTO wallets (user_id, balance) VALUES (?, ?)").run(info.lastInsertRowid, 1000.0); // Give 1000 initial balance for testing

    const token = jwt.sign({ id: info.lastInsertRowid, email, role: 'user' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: info.lastInsertRowid, name, email, role: 'user' } });
  } catch (error: any) {
    if (error.message.includes("UNIQUE constraint failed")) {
      res.status(400).json({ error: "Email already exists" });
    } else {
      res.status(500).json({ error: "Server error" });
    }
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as any;
    if (!user) return res.status(400).json({ error: "User not found" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Dashboard & Wallet
app.get("/api/wallet", authenticateToken, (req: any, res) => {
  const wallet = db.prepare("SELECT balance FROM wallets WHERE user_id = ?").get(req.user.id);
  res.json(wallet);
});

app.get("/api/transactions", authenticateToken, (req: any, res) => {
  const transactions = db.prepare("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC LIMIT 50").all(req.user.id);
  res.json(transactions);
});

// Add Money
app.post("/api/wallet/add", authenticateToken, (req: any, res) => {
  const { amount } = req.body;
  if (amount <= 0) return res.status(400).json({ error: "Invalid amount" });

  const updateWallet = db.prepare("UPDATE wallets SET balance = balance + ? WHERE user_id = ?");
  const insertTxn = db.prepare("INSERT INTO transactions (user_id, type, amount, category, description) VALUES (?, 'income', ?, 'Deposit', 'Added money to wallet')");
  
  const transaction = db.transaction(() => {
    updateWallet.run(amount, req.user.id);
    insertTxn.run(req.user.id, amount);
  });

  try {
    transaction();
    res.json({ success: true, message: "Money added successfully" });
  } catch (error) {
    res.status(500).json({ error: "Transaction failed" });
  }
});

// Send Money
app.post("/api/wallet/send", authenticateToken, (req: any, res) => {
  const { email, amount } = req.body;
  if (amount <= 0) return res.status(400).json({ error: "Invalid amount" });

  const receiver = db.prepare("SELECT id FROM users WHERE email = ?").get(email) as any;
  if (!receiver) return res.status(404).json({ error: "Receiver not found" });

  const senderWallet = db.prepare("SELECT balance FROM wallets WHERE user_id = ?").get(req.user.id) as any;
  if (senderWallet.balance < amount) return res.status(400).json({ error: "Insufficient balance" });

  const updateSender = db.prepare("UPDATE wallets SET balance = balance - ? WHERE user_id = ?");
  const updateReceiver = db.prepare("UPDATE wallets SET balance = balance + ? WHERE user_id = ?");
  const insertSenderTxn = db.prepare("INSERT INTO transactions (user_id, type, amount, category, description) VALUES (?, 'expense', ?, 'Transfer', ?)");
  const insertReceiverTxn = db.prepare("INSERT INTO transactions (user_id, type, amount, category, description) VALUES (?, 'income', ?, 'Transfer', ?)");

  const transaction = db.transaction(() => {
    updateSender.run(amount, req.user.id);
    updateReceiver.run(amount, receiver.id);
    insertSenderTxn.run(req.user.id, amount, `Sent to ${email}`);
    insertReceiverTxn.run(receiver.id, amount, `Received from ${req.user.email}`);
  });

  try {
    transaction();
    res.json({ success: true, message: "Money sent successfully" });
  } catch (error) {
    res.status(500).json({ error: "Transaction failed" });
  }
});

// Add Expense/Income
app.post("/api/transactions", authenticateToken, (req: any, res) => {
  const { type, amount, category, description } = req.body;
  
  const updateWallet = db.prepare(`UPDATE wallets SET balance = balance ${type === 'expense' ? '-' : '+'} ? WHERE user_id = ?`);
  const insertTxn = db.prepare("INSERT INTO transactions (user_id, type, amount, category, description) VALUES (?, ?, ?, ?, ?)");

  const transaction = db.transaction(() => {
    updateWallet.run(amount, req.user.id);
    insertTxn.run(req.user.id, type, amount, category, description);
  });

  try {
    transaction();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: "Failed to add transaction" });
  }
});

// Admin routes
app.get("/api/admin/users", authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const users = db.prepare("SELECT id, name, email, role, created_at FROM users").all();
  res.json(users);
});

app.get("/api/admin/transactions", authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const transactions = db.prepare("SELECT t.*, u.email FROM transactions t JOIN users u ON t.user_id = u.id ORDER BY date DESC").all();
  res.json(transactions);
});

// Vite middleware for development
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
