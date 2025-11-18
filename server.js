// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database('db.sqlite', (err) => {
  if (err) {
    console.error("Erro ao conectar ao banco:", err);
  } else {
    console.log("Banco SQLite conectado.");
  }
});

// ENV
const JWT_SECRET = process.env.JWT_SECRET || 'troque_isto_para_producao';
const PORT = process.env.PORT || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json());

// Criar tabela se não existir
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT,
    endereco TEXT,
    email TEXT UNIQUE,
    password_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => {
  if (err) console.error("Erro ao criar tabela:", err);
});

// ==================== ROTAS ====================

// Rota de teste
app.get('/', (req, res) => {
  res.json({ ok: true, environment: process.env.NODE_ENV || 'development' });
});

// Registro
app.post('/api/auth/register', (req, res) => {
  const { nome, endereco, email, senha } = req.body;

  if (!email || !senha)
    return res.status(400).json({ error: "Email e senha são obrigatórios" });

  if (senha.length < 6)
    return res.status(400).json({ error: "A senha precisa ter pelo menos 6 caracteres" });

  db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: "Erro no banco" });
    if (row) return res.status(409).json({ error: "Usuário já cadastrado" });

    const hash = await bcrypt.hash(senha, 10);

    db.run(
      'INSERT INTO users (nome, endereco, email, password_hash) VALUES (?,?,?,?)',
      [nome || '', endereco || '', email, hash],
      function (err) {
        if (err) return res.status(500).json({ error: "Erro ao salvar usuário" });

        return res.status(201).json({
          id: this.lastID,
          message: "Conta criada com sucesso!"
        });
      }
    );
  });
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha)
    return res.status(400).json({ error: "Email e senha são obrigatórios" });

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "Erro no banco" });
    if (!user) return res.status(401).json({ error: "Credenciais inválidas" });

    const ok = await bcrypt.compare(senha, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Credenciais inválidas" });

    const token = jwt.sign(
      { sub: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: {
        id: user.id,
        nome: user.nome,
        email: user.email,
        endereco: user.endereco
      }
    });
  });
});

// Middleware de autenticação
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Sem token' });

  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Token inválido' });

  const token = parts[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// Rota protegida (perfil)
app.get('/api/me', authMiddleware, (req, res) => {
  db.get(
    'SELECT id, nome, email, endereco, created_at FROM users WHERE id = ?',
    [req.userId],
    (err, user) => {
      if (err) return res.status(500).json({ error: "Erro no banco" });
      if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

      return res.json({ user });
    }
  );
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});
