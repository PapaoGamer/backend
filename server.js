// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const db = new Database('db.sqlite');

const JWT_SECRET = process.env.JWT_SECRET || 'troque_isto_para_producao';
const PORT = process.env.PORT || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

// Cria tabela users se não existir
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT,
    endereco TEXT,
    email TEXT UNIQUE,
    password_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json());

// rota de teste simples
app.get('/', (req, res) => {
  res.json({ ok: true, environment: process.env.NODE_ENV || 'development' });
});

// Registro
app.post('/api/auth/register', async (req, res) => {
  try {
    const { nome, endereco, email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    if (senha.length < 6) return res.status(400).json({ error: 'Senha precisa ter pelo menos 6 caracteres' });

    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return res.status(409).json({ error: 'Usuário já cadastrado' });

    const saltRounds = 10;
    const hash = await bcrypt.hash(senha, saltRounds);

    const stmt = db.prepare('INSERT INTO users (nome, endereco, email, password_hash) VALUES (?,?,?,?)');
    const info = stmt.run(nome || '', endereco || '', email, hash);

    return res.status(201).json({ id: info.lastInsertRowid, message: 'Conta criada' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Erro no servidor' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ error: 'Email e senha são obrigatórios' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Credenciais inválidas' });

    const ok = await bcrypt.compare(senha, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciais inválidas' });

    const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    return res.json({ token, user: { id: user.id, nome: user.nome, email: user.email, endereco: user.endereco } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Erro no servidor' });
  }
});

// Middleware: verifica JWT
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
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// Rota protegida - obter perfil
app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, nome, email, endereco, created_at FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  return res.json({ user });
});

app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});