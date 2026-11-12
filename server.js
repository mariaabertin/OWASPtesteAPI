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
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ erro: 'Header Authorization ausente. Envie: Authorization: Bearer SEU_TOKEN' });
  }
  // Aceita "Bearer token" (maiusculas/espacos extras) e ignora aspas coladas por engano
  const token = header.replace(/^Bearer\s+/i, '').replace(/^["']|["']$/g, '').trim();
  try {
    req.user = jwt.verify(token, SECRET); // { id, role }
    next();
  } catch (e) {
    // e.message diz o motivo real: "jwt malformed", "jwt expired", "invalid signature"...
    res.status(401).json({ erro: 'Token invalido: ' + e.message });
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
 
// ============================================================
// Painel de testes (so para facilitar a demo, nao e parte da API)
// Abra http://localhost:3000 no navegador
// ============================================================
app.get('/', (req, res) => {
  res.type('html').send(String.raw`<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Painel de testes - Carteira API</title>
<style>
  body { font-family: sans-serif; max-width: 820px; margin: 20px auto; padding: 0 12px; }
  fieldset { margin-bottom: 14px; border-radius: 6px; }
  legend { font-weight: bold; }
  input { margin: 3px 0; padding: 4px; }
  button { padding: 5px 10px; margin: 3px 3px 3px 0; cursor: pointer; }
  #modo { padding: 10px; border-radius: 6px; font-weight: bold; }
  .vuln { background: #ffd6d6; }
  .safe { background: #d6ffd9; }
  pre { background: #222; color: #0f0; padding: 12px; border-radius: 6px; min-height: 120px; white-space: pre-wrap; }
</style>
</head>
<body>
<h2>Painel de testes - Carteira Digital</h2>
 
<div id="modo" class="vuln">
  <label><input type="checkbox" id="secure" onchange="atualizaModo()"> Ativar modo SEGURO (?secure=true)</label>
  <span id="modoTxt"> - Modo atual: VULNERAVEL</span>
</div>
<p id="who"><b>Nao logado.</b></p>
<div id="tokenArea" style="display:none; margin-bottom:14px;">
  <b>Para usar no Postman / curl (mesmo token que o painel esta usando):</b><br>
  Header <code>Authorization</code> =
  <input id="hdrValor" readonly size="70" style="font-family:monospace; font-size:11px;">
  <button onclick="copiaHeader()">Copiar</button> <span id="copiado"></span>
</div>
 
<fieldset>
  <legend>0. Login (gera o token)</legend>
  <button onclick="login('maria@teste.com','123')">Entrar como Maria (user)</button>
  <button onclick="login('thaynara@teste.com','123')">Entrar como Thaynara (user)</button>
  <button onclick="login('admin@teste.com','admin')">Entrar como Admin</button><br>
  Outro usuario: <input id="lemail" placeholder="email"> <input id="lsenha" placeholder="senha">
  <button onclick="login($('lemail').value,$('lsenha').value)">Entrar</button>
</fieldset>
 
<fieldset>
  <legend>1. BOLA - GET /accounts/:id</legend>
  ID da conta: <input id="accId" value="2" size="4">
  <button onclick="call('GET','/accounts/'+$('accId').value+q())">Consultar conta</button>
</fieldset>
 
<fieldset>
  <legend>2. BOPLA / Mass Assignment - POST /users</legend>
  Nome: <input id="uNome" value="Hacker">
  E-mail: <input id="uEmail" value="hacker@teste.com">
  Senha: <input id="uSenha" value="1"><br>
  Campos extras (injecao): role: <input id="uRole" value="admin" size="8">
  balance: <input id="uBal" value="9999" size="8">
  <button onclick="criaUsuario()">Criar usuario</button>
</fieldset>
 
<fieldset>
  <legend>3. BFLA - DELETE /admin/users/:id</legend>
  ID do usuario a deletar: <input id="delId" value="2" size="4">
  <button onclick="call('DELETE','/admin/users/'+$('delId').value+q())">Deletar usuario</button>
</fieldset>
 
<fieldset>
  <legend>Auxiliar</legend>
  <button onclick="call('GET','/debug/users')">Listar usuarios (GET /debug/users)</button>
</fieldset>
 
<fieldset>
  <legend>Requisição manual: simulando o header</legend>
  Metodo:
  <select id="mMetodo"><option>GET</option><option>POST</option><option>DELETE</option></select>
  URL: <input id="mUrl" value="/accounts/2" size="40"><br>
  Header Authorization: <input id="mAuth" size="70" placeholder="Bearer SEU_TOKEN (preenchido ao fazer login)"><br>
  Body (JSON, so para POST):<br>
  <textarea id="mBody" rows="3" cols="70" placeholder='{"name":"X","email":"x@teste.com","password":"1"}'></textarea><br>
  <button onclick="manual()">Enviar requisicao</button>
</fieldset>
 
<h3>Resposta da API</h3>
<pre id="out">Aguardando requisicao...</pre>
 
<script>
  var token = '';
  function $(id) { return document.getElementById(id); }
  function q() { return $('secure').checked ? '?secure=true' : ''; }
 
  function atualizaModo() {
    var seguro = $('secure').checked;
    $('modo').className = seguro ? 'safe' : 'vuln';
    $('modoTxt').textContent = seguro ? ' - Modo atual: CORRIGIDO' : ' - Modo atual: VULNERAVEL';
  }
 
  async function call(method, url, body) {
    var headers = {};
    if (body) headers['Content-Type'] = 'application/json';
    if (token) headers['Authorization'] = 'Bearer ' + token;
    try {
      var r = await fetch(url, { method: method, headers: headers, body: body ? JSON.stringify(body) : undefined });
      var data = await r.json();
      var enviado = token ? '\nAuthorization: Bearer ' + token.slice(0, 25) + '...' : '\n(sem header Authorization)';
      $('out').textContent = method + ' ' + url + enviado + '\nStatus: ' + r.status + '\n\n' + JSON.stringify(data, null, 2);
      return data;
    } catch (e) {
      $('out').textContent = 'Erro ao chamar a API: ' + e.message;
    }
  }
 
  async function login(email, senha) {
    var d = await call('POST', '/login', { email: email, password: senha });
    if (d && d.token) {
      token = d.token;
      $('who').innerHTML = '<b>Logado como: ' + email + '</b>';
      $('hdrValor').value = 'Bearer ' + token;
      $('mAuth').value = 'Bearer ' + token;
      $('tokenArea').style.display = 'block';
      $('copiado').textContent = '';
    }
  }
 
  async function manual() {
    var metodo = $('mMetodo').value;
    var url = $('mUrl').value.trim();
    var auth = $('mAuth').value.trim();
    var corpo = $('mBody').value.trim();
    var headers = {};
    if (auth) headers['Authorization'] = auth;
    if (corpo) headers['Content-Type'] = 'application/json';
    try {
      var r = await fetch(url, { method: metodo, headers: headers, body: corpo ? corpo : undefined });
      var data = await r.json();
      $('out').textContent = metodo + ' ' + url + '\nAuthorization: ' + (auth || '(nenhum)') + '\nStatus: ' + r.status + '\n\n' + JSON.stringify(data, null, 2);
    } catch (e) {
      $('out').textContent = 'Erro ao enviar: ' + e.message;
    }
  }
 
  function copiaHeader() {
    $('hdrValor').select();
    navigator.clipboard.writeText($('hdrValor').value).then(function () {
      $('copiado').textContent = 'Copiado!';
    });
  }
 
  function criaUsuario() {
    var body = { name: $('uNome').value, email: $('uEmail').value, password: $('uSenha').value };
    if ($('uRole').value) body.role = $('uRole').value;
    if ($('uBal').value) body.balance = Number($('uBal').value);
    call('POST', '/users' + q(), body);
  }
</script>
</body>
</html>`);
});
 
app.listen(3000, () => console.log('API rodando em http://localhost:3000'));
 