require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");

const app = express();
app.use(express.json()); // supaya req.body terbaca

// =================== KONEKSI DATABASE ===================
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});


// =================== MIDDLEWARE JWT ===================
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Token tidak ditemukan" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token tidak valid" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret123");
    req.driver = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Token tidak valid atau expired" });
  }
}

// =================== ROUTE REGISTER ===================
app.post("/register", async (req, res) => {
  try {
    const { nama, email, no_hp, password, alamat = null, kendaraan = null } = req.body;

    // Validasi input wajib
    if (!nama || !email || !no_hp || !password) {
      return res.status(400).json({ message: "Data tidak lengkap" });
    }

    // Cek apakah email sudah terdaftar
    const [rows] = await db.query("SELECT id FROM drivers WHERE email = ?", [email]);
    if (rows.length > 0) {
      return res.status(400).json({ message: "Email sudah terdaftar" });
    }

    // Hash password
    const hash = await bcrypt.hash(password, 10);

    // Simpan data driver baru
    await db.query(
      `INSERT INTO drivers (nama, email, no_hp, password_hash, alamat, kendaraan)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [nama, email, no_hp, hash, alamat, kendaraan]
    );

    res.status(201).json({ message: "Registrasi berhasil, status: pending" });
  } catch (err) {
    console.error("ERROR REGISTER:", err.message);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// =================== ROUTE LOGIN ===================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Email atau password kosong" });

    const [rows] = await db.query("SELECT * FROM drivers WHERE email = ?", [email]);
    if (rows.length === 0) return res.status(400).json({ message: "Email tidak ditemukan" });

    const driver = rows[0];

    // Cek password
    const match = await bcrypt.compare(password, driver.password_hash);
    if (!match) return res.status(400).json({ message: "Password salah" });

    // Buat token JWT
    const token = jwt.sign(
      { id: driver.id, email: driver.email },
      process.env.JWT_SECRET || "secret123",
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login berhasil",
      token,
      driver: {
        id: driver.id,
        nama: driver.nama,
        email: driver.email,
        no_hp: driver.no_hp,
        alamat: driver.alamat,
        kendaraan: driver.kendaraan,
        status: driver.status
      }
    });
  } catch (err) {
    console.error("ERROR LOGIN:", err.message);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// =================== ROUTE PROFILE ===================
app.get("/profile", verifyToken, async (req, res) => {
  try {
    const driverId = req.driver.id;
    const [rows] = await db.query(
      "SELECT id, nama, email, no_hp, alamat, kendaraan, status FROM drivers WHERE id = ?",
      [driverId]
    );

    if (rows.length === 0)
      return res.status(404).json({ message: "Driver tidak ditemukan" });

    res.json({ driver: rows[0] });
  } catch (err) {
    console.error("ERROR PROFILE:", err.message);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// =================== ROUTE TEST ===================
app.post("/coba", (req, res) => {
  res.send("POST /coba berhasil");
});

// =================== ROUTE DEFAULT ===================
app.get("/", (req, res) => {
  res.send("Auth service jalan");
});

// =================== JALANKAN SERVER ===================
const PORT = process.env.PORT || 3000; // Railway / Render akan assign PORT
app.listen(PORT, () => console.log(`Server jalan di port ${PORT}`));
