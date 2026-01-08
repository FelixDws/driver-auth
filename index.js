require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");

const app = express();
app.use(express.json()); // supaya req.body terbaca

// ======= KONEKSI DATABASE =======
const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "", // ganti sesuai MySQLmu
  database: "shopeefood_driver_lampung",
});

// ======= MIDDLEWARE JWT =======
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

// ======= ROUTE REGISTER =======
app.post("/register", async (req, res) => {
  try {
    const { nama, email, no_hp, password, alamat, kendaraan } = req.body;

    if (!nama || !email || !no_hp || !password) {
      return res.status(400).json({ message: "Data tidak lengkap" });
    }

    const [rows] = await db.query("SELECT id FROM drivers WHERE email = ?", [email]);
    if (rows.length > 0) return res.status(400).json({ message: "Email sudah terdaftar" });

    const hash = await bcrypt.hash(password, 10);

    await db.query(
      `INSERT INTO drivers (nama, email, no_hp, password_hash, alamat, kendaraan)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [nama, email, no_hp, hash, alamat || null, kendaraan || null]
    );

    res.status(201).json({ message: "Registrasi berhasil, status: pending" });
  } catch (err) {
    console.error("ERROR REGISTER:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ======= ROUTE LOGIN =======
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).json({ message: "Email atau password kosong" });

    const [rows] = await db.query("SELECT * FROM drivers WHERE email = ?", [email]);
    if (rows.length === 0) return res.status(400).json({ message: "Email tidak ditemukan" });

    const driver = rows[0];
    const match = await bcrypt.compare(password, driver.password_hash);
    if (!match) return res.status(400).json({ message: "Password salah" });

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
        status: driver.status,
      },
    });
  } catch (err) {
    console.error("ERROR LOGIN:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ======= ROUTE PROFILE (PROTEKSI JWT) =======
app.get("/profile", verifyToken, async (req, res) => {
  try {
    const driverId = req.driver.id;

    const [rows] = await db.query(
      "SELECT id, nama, email, no_hp, alamat, kendaraan, status FROM drivers WHERE id = ?",
      [driverId]
    );

    if (rows.length === 0) return res.status(404).json({ message: "Driver tidak ditemukan" });

    res.json({ driver: rows[0] });
  } catch (err) {
    console.error("ERROR PROFILE:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ======= ROUTE TEST =======
app.post("/coba", (req, res) => {
  res.send("POST /coba berhasil");
});

// ======= DEFAULT =======
app.get("/", (req, res) => {
  res.send("Auth service jalan");
});

// ======= JALANKAN SERVER =======
const PORT = 3000;
app.listen(PORT, () => console.log(`Server jalan di port ${PORT}`));
