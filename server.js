const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

const users = [];

const SECRET_KEY = 'yourSecretKey'; // Replace with a strong secret key

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store the user data
    users.push({ username, password: hashedPassword });

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Authentication and authorization middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Autenticación de usuario y generación de token
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Buscar al usuario en la lista de usuarios
    const user = users.find(user => user.username === username);

    if (!user) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    // Verificar la contraseña
    if (await bcrypt.compare(password, user.password)) {
      // Generar el token JWT
      const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });

      res.json({ token });
    } else {
      res.status(401).json({ error: 'Contraseña incorrecta' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Un error ocurrió' });
  }
});

// Protected resource endpoint
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Protected resource accessed successfully' });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
