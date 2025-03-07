const jwt = require("jsonwebtoken");
const db = require("../models/database");

const JWT_SECRET = 'dasjkai289ud90821yas';

module.exports = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No se proporcionó token" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Token inválido" });
    }

    const sesionQuery = `SELECT * FROM sessions WHERE token = ?`;
    db.get(sesionQuery, [token], (err, session) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!session) {
        return res.status(401).json({ error: "Sesión no válida" });
      }

      req.user = decoded;
      next();
    });
  });
};
