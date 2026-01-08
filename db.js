const mysql = require("mysql2/promise");

const db = mysql.createPool({
  host: "localhost",      // biasanya localhost
  user: "root",           // username MySQL kamu
  password: "",           // password MySQL, kosong jika default
  database: "shopeefood_driver_lampung" // nama database
});

module.exports = db;
