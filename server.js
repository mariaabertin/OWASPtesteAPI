// ============================================================
// API de Carteira Digital - VULNERAVEL DE PROPOSITO
// Como alternar entre os modos:
//   sem parametro       -> comportamento VULNERAVEL
//   ?secure=true        -> comportamento CORRIGIDO
// ============================================================

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

app.get('/', (req, res) => {
  res.json({
    mensagem: 'API de Carteira Digital (testes de vulnerabilidade)',
    rotas: [
      'POST   /login',
      'GET    /accounts/:id',
      'POST   /users',
      'DELETE /admin/users/:id',
      'GET    /debug/users',
    ],
    dica: 'Adicione ?secure=true para ativar a versao corrigida',
  });
});

const SECRET = 'segredo-de-demonstracao';
const isSecure = (req) => req.query.secure === 'true';

// Banco de dados em memoria
let nextId = 4;

const users = [
  { id: 1, name: 'Maria', email: 'maria@teste.com', password: '123', role: 'user' },
  { id: 2, name: 'Thaynara',   email: 'thaynara@teste.com',   password: '123', role: 'user' },
  { id: 3, name: 'Admin', email: 'admin@teste.com', password: 'admin', role: 'admin' },
];

// Cada conta pertence a um usuario (ownerId)
const accounts = [
  { id: 1, ownerId: 1, balance: 1000 },
  { id: 2, ownerId: 2, balance: 500 },
  { id: 3, ownerId: 3, balance: 99999 },
];

// Autenticacao (JWT) 
// Middleware: so confere se o token e valido (AUTENTICACAO).
// Ele NAO decide o que o usuario pode fazer (AUTORIZACAO).
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, SECRET); // { id, role }
    next();
  } catch (e) {
    res.status(401).json({ erro: 'Token ausente ou invalido' });
  }
}

// Login: devolve um token com id e role do usuario
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ erro: 'Credenciais invalidas' });

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
  res.json({ token });
});


// BOLA (Broken Object Level Authorization)
// GET /accounts/:id
app.get('/accounts/:id', auth, (req, res) => {
  const account = accounts.find((a) => a.id === Number(req.params.id));
  if (!account) return res.status(404).json({ erro: 'Conta nao encontrada' });

  if (isSecure(req)) {
    // CORRECAO: a conta precisa pertencer ao usuario do token
    if (account.ownerId !== req.user.id) {
      return res.status(403).json({ erro: 'Voce nao pode acessar esta conta' });
    }
  }
  // VULNERAVEL: se chegou aqui, qualquer usuario logado ve qualquer conta

  res.json(account);
});


// BOPLA / Mass Assignment
// POST /users
app.post('/users', (req, res) => {
  let newUser;

  if (isSecure(req)) {
    // CORRECAO: pega SO os campos permitidos; role e saldo sao definidos pelo servidor
    const { name, email, password } = req.body;
    newUser = { id: nextId++, name, email, password, role: 'user' };
    accounts.push({ id: newUser.id, ownerId: newUser.id, balance: 0 });
  } else {
    // VULNERAVEL: copia tudo que o cliente mandou (inclusive role e balance)
    newUser = { id: nextId++, role: 'user', ...req.body };
    accounts.push({ id: newUser.id, ownerId: newUser.id, balance: req.body.balance || 0 });
  }

  users.push(newUser);

  const { password, ...semSenha } = newUser; // nunca devolver a senha
  res.status(201).json(semSenha);
});


// API5:2023 - BFLA (Broken Function Level Authorization)
// DELETE /admin/users/:id
app.delete('/admin/users/:id', auth, (req, res) => {
  if (isSecure(req)) {
    // CORRECAO (RBAC): so quem tem role "admin" executa esta funcao
    if (req.user.role !== 'admin') {
      return res.status(403).json({ erro: 'Apenas administradores' });
    }
  }
  // VULNERAVEL: token valido ja basta, a role nao e verificada

  const index = users.findIndex((u) => u.id === Number(req.params.id));
  if (index === -1) return res.status(404).json({ erro: 'Usuario nao encontrado' });

  const [removido] = users.splice(index, 1);
  res.json({ mensagem: `Usuario ${removido.name} deletado` });
});

// Rota auxiliar so para a demo: ver o estado atual (nao faz parte das vulnerabilidades)
app.get('/debug/users', (req, res) => {
  res.json(users.map(({ password, ...u }) => u));
});

app.listen(3000, () => console.log('API rodando em http://localhost:3000'));
