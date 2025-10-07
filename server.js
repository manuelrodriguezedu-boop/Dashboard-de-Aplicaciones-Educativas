// server.js
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.')); // Sirve index.html y otros archivos estáticos

// Conexión a PostgreSQL
const pool = new Pool({
  user: 'tu_usuario',       // ← ¡Cambia esto!
  host: 'localhost',
  database: 'razonaapp',    // ← ¡Cambia esto!
  password: 'tu_contraseña', // ← ¡Cambia esto!
  port: 5432,
});

// Registro de alumno
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
  }

  try {
    // Verificar si el correo ya existe
    const { rows } = await pool.query('SELECT * FROM Alumnos WHERE Email_Usuario = $1', [email]);
    if (rows.length > 0) {
      return res.status(409).json({ error: 'Este correo ya está registrado.' });
    }

    // Hashear contraseña
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insertar alumno
    const [nombre, ...apellidosArr] = name.trim().split(' ');
    const apellidos = apellidosArr.join(' ') || '';

    await pool.query(
      `INSERT INTO Alumnos (Nombre, Apellidos, Email_Usuario, Password_Hash)
       VALUES ($1, $2, $3, $4)`,
      [nombre, apellidos, email, passwordHash]
    );

    res.status(201).json({ message: 'Registro exitoso. ¡Ahora puedes iniciar sesión!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error en el servidor.' });
  }
});

// Login de alumno
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Correo y contraseña son obligatorios.' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT ID_Alumno, Nombre, Apellidos, Password_Hash FROM Alumnos WHERE Email_Usuario = $1',
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Credenciales incorrectas.' });
    }

    const user = rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);

    if (!isValid) {
      return res.status(401).json({ error: 'Credenciales incorrectas.' });
    }

    // Aquí podrías generar un token JWT si lo deseas
    res.json({
      message: 'Inicio de sesión correcto',
      user: {
        id: user.id_alumno,
        nombre: `${user.nombre} ${user.apellidos}`,
        email: email
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error en el servidor.' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
