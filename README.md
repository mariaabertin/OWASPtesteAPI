# 💳 API de Carteira Digital: OWASP API Security Top 10

Projeto didático para o seminário **"OWASP Top 10 aplicado a APIs"**.

É uma API em Node.js + Express, **vulnerável de propósito**, que demonstra 3 falhas reais e a correção de cada uma.

> ⚠️ **Aviso:** use apenas localmente e para estudo. Nunca coloque este código em produção.

---

## 📦 Como rodar

```bash
npm install
npm start
```

O servidor sobe em `http://localhost:3000`.

> Abrir `http://localhost:3000/` no navegador mostra `Cannot GET /`. Isso é normal: a API não tem rota na raiz. Use as rotas descritas abaixo.

---

## 🧠 Como a aplicação funciona

### Armazenamento
Não há banco de dados. Usuários e contas ficam em **arrays na memória**. Ao reiniciar o servidor, tudo volta ao estado inicial.

### Usuários iniciais

| ID | Nome  | E-mail            | Senha   | Role    | Saldo da conta |
|----|-------|-------------------|---------|---------|----------------|
| 1  | Maria | maria@teste.com   | `123`   | `user`  | 1000           |
| 2  | Thaynara   | thaynara@teste.com     | `123`   | `user`  | 500            |
| 3  | Admin | admin@teste.com   | `admin` | `admin` | 99999          |

### Autenticação com JWT
1. O usuário faz login em `POST /login` e recebe um **token JWT**.
2. O token contém o `id` e a `role` do usuário.
3. Nas rotas protegidas, o cliente envia o token no **header** `Authorization`.

### Alternando entre VULNERÁVEL e CORRIGIDO
Cada rota vulnerável aceita o parâmetro de URL `?secure=true`:

| URL                          | Comportamento           |
|------------------------------|-------------------------|
| `/rota`                      | ❌ Vulnerável           |
| `/rota?secure=true`          | ✅ Corrigido            |

---

## 🔑 Headers usados nas requisições

| Header          | Valor                      | Quando usar                                   |
|-----------------|----------------------------|-----------------------------------------------|
| `Content-Type`  | `application/json`         | Sempre que enviar um **body** (POST)          |
| `Authorization` | `Bearer SEU_TOKEN_AQUI`    | Rotas que exigem login (veja tabela abaixo)   |

> 💡 Troque `SEU_TOKEN_AQUI` pelo token recebido no login. Escreva `Bearer`, um espaço e o token.

---

## 🛣️ Resumo das rotas

| Método   | Rota                    | Precisa de token? | Body (JSON)                              | Vulnerabilidade                              |
|----------|-------------------------|:-----------------:|------------------------------------------|----------------------------------------------|
| `POST`   | `/login`                | ❌ Não            | `email`, `password`                      | (nenhuma, só gera o token)                   |
| `GET`    | `/accounts/:id`         | ✅ Sim            | (sem body)                               | **API1:2023: BOLA**                          |
| `POST`   | `/users`                | ❌ Não            | `name`, `email`, `password` (+ extras)   | **API3:2023: BOPLA / Mass Assignment**       |
| `DELETE` | `/admin/users/:id`      | ✅ Sim            | (sem body)                               | **API5:2023: BFLA**                          |
| `GET`    | `/debug/users`          | ❌ Não            | (sem body)                               | (auxiliar para a demo, lista os usuários)    |

---

## 🔐 Passo 0: Fazer login (obter o token)

**Rota:** `POST /login`

**Headers:**
```
Content-Type: application/json
```

**Body:**
```json
{ "email": "maria@teste.com", "password": "123" }
```

**Resposta:**
```json
{ "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
```

Copie o token. Ele será usado nas demonstrações 1 e 3.
Para testar como outro usuário, faça login com outro e-mail (Bob, Admin).

---

## 🚨 Vulnerabilidade 1: BOLA (API1:2023)

**Broken Object Level Authorization**: a API não verifica se o **objeto** (a conta) pertence a quem está pedindo.

**Rota:** `GET /accounts/:id`

**Headers:**
```
Authorization: Bearer TOKEN_DA_ALICE
```

### Ataque
A Maria (id 1) troca o ID na URL para ver a conta da Thaynara (id 2).

| Modo           | URL                                  | Resultado                                  |
|----------------|--------------------------------------|--------------------------------------------|
| ❌ Vulnerável  | `/accounts/2`                        | `200 OK`: mostra o saldo da Thaynara            |
| ✅ Corrigido   | `/accounts/2?secure=true`            | `403`: "Voce nao pode acessar esta conta"  |

### Causa
O servidor só confere se o token é válido, mas não compara o dono da conta com o usuário do token.

### Correção
```js
if (account.ownerId !== req.user.id) {
  return res.status(403).json({ erro: 'Voce nao pode acessar esta conta' });
}
```

---

## 🚨 Vulnerabilidade 2: BOPLA / Mass Assignment (API3:2023)

**Broken Object Property Level Authorization**: a API aceita **propriedades** que o cliente não deveria poder definir.

**Rota:** `POST /users`

**Headers:**
```
Content-Type: application/json
```

**Body (o cliente envia campos extras `role` e `balance`):**
```json
{
  "name": "Hacker",
  "email": "hacker@teste.com",
  "password": "1",
  "role": "admin",
  "balance": 9999
}
```

### Ataque

| Modo           | URL                      | Resultado                                              |
|----------------|--------------------------|--------------------------------------------------------|
| ❌ Vulnerável  | `/users`                 | Usuário criado com `role: "admin"` e saldo 9999        |
| ✅ Corrigido   | `/users?secure=true`     | `role` e `balance` ignorados: vira `user`, saldo 0     |

### Causa
O código copia todo o `req.body` para o novo usuário:
```js
newUser = { id: nextId++, role: 'user', ...req.body };
```

### Correção
Aceitar apenas os campos permitidos e definir os privilegiados no servidor:
```js
const { name, email, password } = req.body;
newUser = { id: nextId++, name, email, password, role: 'user' };
```

> 💡 Confira o resultado em `GET /debug/users`.

---

## 🚨 Vulnerabilidade 3: BFLA (API5:2023)

**Broken Function Level Authorization**: a API não verifica se o usuário tem permissão para executar aquela **função** (aqui, uma função administrativa).

**Rota:** `DELETE /admin/users/:id`

**Headers:**
```
Authorization: Bearer TOKEN_DA_ALICE
```

### Ataque
A Maria, que é usuária comum, tenta deletar o Thaynara (id 2).

| Modo           | URL                                  | Resultado                                |
|----------------|--------------------------------------|------------------------------------------|
| ❌ Vulnerável  | `/admin/users/2`                     | `200 OK`: "Usuario Thaynara deletado"         |
| ✅ Corrigido   | `/admin/users/2?secure=true`         | `403`: "Apenas administradores"          |

### Causa
O servidor verifica se o token é válido (autenticação), mas não verifica a **role** (autorização).

### Correção (RBAC: controle de acesso baseado em papéis)
```js
if (req.user.role !== 'admin') {
  return res.status(403).json({ erro: 'Apenas administradores' });
}
```

---

## Bônus: encadeando as falhas

1. Crie um usuário `admin` pela falha de **Mass Assignment** (`POST /users` com `"role": "admin"`).
2. Faça login com esse novo usuário em `POST /login`.
3. Use o token dele para deletar qualquer conta em `DELETE /admin/users/:id`.

Uma falha pequena de validação vira controle total do sistema.

---

## 📚 Vulnerabilidades exemplificadas

| Vulnerabilidade | O que falha?        | Pergunta que a API esqueceu de fazer          |
|-----------------|---------------------|-----------------------------------------------|
| **BOLA**        | Acesso ao *objeto*  | "Este objeto pertence a **você**?"            |
| **BOPLA**       | Acesso à *propriedade* | "Você pode definir **este campo**?"        |
| **BFLA**        | Acesso à *função*   | "Você tem permissão para **esta ação**?"      |

**Ideia central:** *autenticação* (quem é você?) é diferente de *autorização* (o que você pode fazer?). Nas três falhas, a API só fez a primeira.

---

## 🧯 Simplificações (só para a demo)

- Senhas em **texto puro**.
- Segredo do JWT **fixo no código**.
- Dados em memória, sem banco de dados.

## 🔎 Referência

[OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)