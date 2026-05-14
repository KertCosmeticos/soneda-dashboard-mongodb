const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));
const frontendPath = path.resolve(__dirname, "../../frontend");

app.use(express.static(frontendPath));

const PORT = process.env.PORT || 3000;
const uri = process.env.MONGODB_URI;
const dbName = process.env.DB_NAME || "soneda_dashboard";

const client = new MongoClient(uri);

// ─────────────────────────────────────────
// UPLOAD
// ─────────────────────────────────────────
const upload = multer({ dest: "uploads/" });

// ─────────────────────────────────────────
// E-MAIL
// ─────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ─────────────────────────────────────────
// AUTH — SESSÕES
// ─────────────────────────────────────────
const sessoes      = new Map();
const sessoesAdmin = new Map();

const TOKEN_EXPIRY_MS       = 8 * 60 * 60 * 1000;
const RESET_TOKEN_EXPIRY_MS = 30 * 60 * 1000; // 30 min

function gerarToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashSenha(senha) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(senha, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verificarSenha(senha, hashArmazenado) {
  const [salt, hash] = hashArmazenado.split(":");
  const hashTeste = crypto.scryptSync(senha, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(hashTeste, "hex"));
}

function verificarToken(req, res, next) {
  const auth  = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token || !sessoes.has(token)) return res.status(401).json({ erro: "Não autorizado." });
  const sessao = sessoes.get(token);
  if (Date.now() > sessao.expira) {
    sessoes.delete(token);
    return res.status(401).json({ erro: "Sessão expirada." });
  }
  req.usuarioLogado = sessao.usuario || "desconhecido";
  next();
}

function verificarTokenAdmin(req, res, next) {
  const auth  = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token || !sessoesAdmin.has(token)) return res.status(401).json({ erro: "Não autorizado." });
  const sessao = sessoesAdmin.get(token);
  if (Date.now() > sessao.expira) {
    sessoesAdmin.delete(token);
    return res.status(401).json({ erro: "Sessão expirada." });
  }
  next();
}

// ─────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────
function limparValor(valor) {
  if (valor === undefined || valor === null) return "";
  return String(valor).replace(/^﻿/, '').trim();
}

function parseBRNumber(val) {
  let s = String(val ?? '').trim().replace(/^R\$\s*/i, '');
  if (/^\d{1,3}(?:\.\d{3})*,\d+$/.test(s) || /^\d+,\d+$/.test(s)) {
    return parseFloat(s.replace(/\./g, '').replace(',', '.'));
  }
  return val;
}

function brToDouble(expr) {
  // Strip "R$ " / "R$" prefix, remove thousands dots, replace comma decimal → double
  const str = { $toString: { $ifNull: [expr, "0"] } };
  const noPrefix = {
    $replaceAll: {
      input: { $replaceAll: { input: str, find: "R$ ", replacement: "" } },
      find: "R$", replacement: ""
    }
  };
  return {
    $convert: {
      input: {
        $replaceAll: {
          input: { $replaceAll: { input: noPrefix, find: ".", replacement: "" } },
          find: ",", replacement: "."
        }
      },
      to: "double", onError: 0, onNull: 0
    }
  };
}

// Tries "Venda (R$)" first; if 0, tries "Venda Pdv Valor" then "Venda Nf Valor"
function brValorExpr() {
  const rv  = brToDouble({ $getField: "Venda (R$)" });
  const pdv = brToDouble({ $getField: "Venda Pdv Valor" });
  const nf  = brToDouble({ $getField: "Venda Nf Valor"  });
  return { $cond: [{ $gt: [rv, 0] }, rv, { $cond: [{ $gt: [pdv, 0] }, pdv, nf] }] };
}

// ─────────────────────────────────────────
// SERVIDOR
// ─────────────────────────────────────────
async function iniciarServidor() {
  try {
    await client.connect();
    const db = client.db(dbName);

    console.log("✅ Conectado ao MongoDB");
    console.log(`📦 Banco em uso: ${dbName}`);

    // Seed usuário inicial de importação a partir das variáveis de ambiente
    const totalUsuarios = await db.collection("usuarios_importacao").countDocuments();
    if (totalUsuarios === 0 && process.env.ADMIN_USER && process.env.ADMIN_PASSWORD) {
      await db.collection("usuarios_importacao").insertOne({
        usuario:  process.env.ADMIN_USER,
        senha:    hashSenha(process.env.ADMIN_PASSWORD),
        email:    process.env.EMAIL_USER || "",
        criadoEm: new Date()
      });
      console.log(`👤 Usuário de importação inicial criado: ${process.env.ADMIN_USER}`);
    }

    // Seed templates de importação
    const templatesSeed = [
      {
        filename: "modelo_dados_brutos.csv",
        nome:     "Dados Brutos",
        conteudo: "Ano;Mês;Data;Loja;GTIN/PLU;Produto;Venda (Qtd);Venda (R$);Estoque Diario\n2025;Jan;01/01/2025;001;7891234567890;Produto Exemplo;10;150,00;50\n"
      },
      {
        filename: "modelo_categorias_depara.csv",
        nome:     "De/Para Categorias",
        conteudo: "CODBARRAS;CATEGORIA;FAMILIA;NOME PRODUTO\n7891234567890;Cosméticos;Hidratantes;Creme Hidratante Corporal 200ml\n"
      },
      {
        filename: "modelo_lojas_depara.csv",
        nome:     "De/Para Lojas",
        conteudo: "Cod_Loja;Nome_Fantasia\n001;Loja Centro\n"
      }
    ];
    for (const t of templatesSeed) {
      const existe = await db.collection("templates_importacao").findOne({ filename: t.filename });
      if (!existe) {
        await db.collection("templates_importacao").insertOne({ ...t, atualizadoEm: new Date() });
        console.log(`📄 Template criado: ${t.filename}`);
      }
    }

    // Seed super-admin no MongoDB (permite reset de senha por e-mail)
    const adminExistente = await db.collection("usuarios_admin").findOne({ usuario: process.env.ADMIN_USER });
    if (!adminExistente && process.env.ADMIN_USER && process.env.ADMIN_PASSWORD) {
      await db.collection("usuarios_admin").insertOne({
        usuario:  process.env.ADMIN_USER,
        senha:    hashSenha(process.env.ADMIN_PASSWORD),
        email:    process.env.ADMIN_EMAIL || "",
        criadoEm: new Date()
      });
      console.log(`🔐 Super-admin criado no MongoDB: ${process.env.ADMIN_USER}`);
    } else if (adminExistente && process.env.ADMIN_EMAIL && !adminExistente.email) {
      // Atualiza e-mail se ainda não estava cadastrado
      await db.collection("usuarios_admin").updateOne(
        { usuario: process.env.ADMIN_USER },
        { $set: { email: process.env.ADMIN_EMAIL } }
      );
    }

    // Garante índice único no campo usuario
    await db.collection("usuarios_importacao").createIndex({ usuario: 1 }, { unique: true });

    // Índices de performance para dados_brutos (queries de dashboard)
    await Promise.all([
      // Compostos cobrem $match de período + $group por dimensão
      db.collection("dados_brutos").createIndex({ "Ano": 1, "Mês": 1, "Loja": 1 }),
      db.collection("dados_brutos").createIndex({ "Ano": 1, "Mês": 1, "Data": 1 }),
      db.collection("dados_brutos").createIndex({ "Ano": 1, "Mês": 1 }),
      db.collection("dados_brutos").createIndex({ "Loja": 1 }),
      db.collection("dados_brutos").createIndex({ "GTIN/PLU": 1 }),
      db.collection("categorias_depara").createIndex({ "CODBARRAS": 1 })
    ]);
    console.log("📊 Índices de dashboard criados/verificados");

    // TTL automático para tokens de reset expirados (importação e admin)
    await db.collection("tokens_reset").createIndex({ expira: 1 }, { expireAfterSeconds: 0 });

    app.get("/", (req, res) => {
      res.sendFile(path.join(frontendPath, "index.html"));
    });

    app.get("/reset-senha", (req, res) => {
      res.sendFile(path.join(frontendPath, "reset-senha.html"));
    });

    // ─────────────────────────────────────
    // TEMPLATES DE IMPORTAÇÃO
    // ─────────────────────────────────────

    // Download público — sem autenticação
    app.get("/api/templates/:filename", async (req, res) => {
      try {
        const template = await db.collection("templates_importacao").findOne({ filename: req.params.filename });
        if (!template) return res.status(404).json({ erro: "Template não encontrado." });
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="${template.filename}"`);
        res.send("﻿" + template.conteudo); // BOM para compatibilidade com Excel
      } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar template." });
      }
    });

    // Listar templates (admin)
    app.get("/api/admin/templates", verificarTokenAdmin, async (req, res) => {
      try {
        const templates = await db
          .collection("templates_importacao")
          .find({}, { projection: { conteudo: 0 } })
          .sort({ nome: 1 })
          .toArray();
        res.json(templates);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao listar templates." });
      }
    });

    // Upload / substituir template (admin)
    app.put("/api/admin/templates/:filename", verificarTokenAdmin, upload.single("file"), async (req, res) => {
      const { filename } = req.params;
      if (!req.file) return res.status(400).json({ erro: "Nenhum arquivo enviado." });

      try {
        const conteudo = fs.readFileSync(req.file.path, "utf-8");
        fs.unlinkSync(req.file.path);

        const result = await db.collection("templates_importacao").updateOne(
          { filename },
          { $set: { conteudo, atualizadoEm: new Date() } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ erro: "Template não encontrado. Verifique o nome do arquivo." });
        }

        res.json({ ok: true });
      } catch (error) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.status(500).json({ erro: "Erro ao salvar template.", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // LOGIN / LOGOUT (importação)
    // ─────────────────────────────────────
    app.post("/api/login", async (req, res) => {
      const { usuario, senha } = req.body;
      if (!usuario || !senha) return res.status(401).json({ erro: "Usuário ou senha inválidos." });

      try {
        const user = await db.collection("usuarios_importacao").findOne({ usuario });
        if (!user || !verificarSenha(senha, user.senha)) {
          return res.status(401).json({ erro: "Usuário ou senha inválidos." });
        }
        const token = gerarToken();
        sessoes.set(token, { expira: Date.now() + TOKEN_EXPIRY_MS, usuario: user.usuario });
        return res.json({ token });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao verificar credenciais." });
      }
    });

    app.post("/api/logout", (req, res) => {
      const auth  = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (token) sessoes.delete(token);
      res.json({ ok: true });
    });

    // ─────────────────────────────────────
    // RESET DE SENHA (importação)
    // ─────────────────────────────────────
    app.post("/api/solicitar-reset", async (req, res) => {
      const { usuario } = req.body;

      // Sempre responde com a mesma mensagem para não vazar se o usuário existe
      const respostaNeutra = { ok: true, mensagem: "Se o usuário existir e tiver um e-mail cadastrado, você receberá as instruções em breve." };

      if (!usuario) return res.json(respostaNeutra);

      try {
        const user = await db.collection("usuarios_importacao").findOne({ usuario });
        if (!user || !user.email) return res.json(respostaNeutra);

        // Remove tokens antigos do mesmo usuário
        await db.collection("tokens_reset").deleteMany({ usuarioId: user._id });

        const token = gerarToken();
        const expira = new Date(Date.now() + RESET_TOKEN_EXPIRY_MS);

        await db.collection("tokens_reset").insertOne({
          token,
          usuarioId: user._id,
          expira
        });

        const baseUrl = `${req.protocol}://${req.get("host")}`;
        const link = `${baseUrl}/reset-senha?token=${token}`;

        await transporter.sendMail({
          from: `"Painel Soneda" <${process.env.EMAIL_USER}>`,
          to: user.email,
          subject: "Redefinição de senha — Painel Soneda",
          html: `
            <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#0d0f14;color:#e8ecf5;border-radius:12px">
              <h2 style="font-size:1.4rem;margin-bottom:8px;color:#c8f135">Redefinição de senha</h2>
              <p style="color:#8891aa;font-size:0.9rem;margin-bottom:24px">Painel Soneda · Área de Importação</p>
              <p style="margin-bottom:20px">Olá, <strong>${user.usuario}</strong>.</p>
              <p style="margin-bottom:24px">Recebemos uma solicitação para redefinir sua senha. Clique no botão abaixo para criar uma nova senha. O link é válido por <strong>30 minutos</strong> e pode ser usado apenas uma vez.</p>
              <a href="${link}" style="display:inline-block;background:#c8f135;color:#0d0f14;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:0.9rem;margin-bottom:24px">
                Redefinir minha senha
              </a>
              <p style="color:#5a6080;font-size:0.78rem;margin-top:24px;border-top:1px solid #252a3a;padding-top:16px">
                Se você não solicitou a redefinição de senha, ignore este e-mail. Sua senha permanece a mesma.<br><br>
                Link alternativo: <a href="${link}" style="color:#c8f135">${link}</a>
              </p>
            </div>
          `
        });

        console.log(`📧 E-mail de reset enviado para ${user.email}`);
        res.json(respostaNeutra);
      } catch (error) {
        console.error("❌ Erro ao enviar e-mail de reset:", error.code, error.message);
        res.status(500).json({
          erro: "Erro ao enviar e-mail. Tente novamente.",
          detalhe: `[${error.code || "ERR"}] ${error.message}`
        });
      }
    });

    app.post("/api/redefinir-senha", async (req, res) => {
      const { token, novaSenha } = req.body;
      if (!token || !novaSenha) return res.status(400).json({ erro: "Dados inválidos." });

      try {
        const registro = await db.collection("tokens_reset").findOne({ token });

        if (!registro) return res.status(400).json({ erro: "Link inválido ou já utilizado." });
        if (new Date() > registro.expira) {
          await db.collection("tokens_reset").deleteOne({ token });
          return res.status(400).json({ erro: "Este link expirou. Solicite um novo." });
        }

        // Decide qual coleção atualizar com base no tipo do token
        const colecao = registro.tipo === "admin" ? "usuarios_admin" : "usuarios_importacao";
        await db.collection(colecao).updateOne(
          { _id: registro.usuarioId },
          { $set: { senha: hashSenha(novaSenha) } }
        );

        await db.collection("tokens_reset").deleteOne({ token });

        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao redefinir senha." });
      }
    });

    // ─────────────────────────────────────
    // LOGIN / LOGOUT (gestão de usuários)
    // ─────────────────────────────────────
    app.post("/api/admin/login", async (req, res) => {
      const { usuario, senha } = req.body;
      if (!usuario || !senha) return res.status(401).json({ erro: "Usuário ou senha inválidos." });

      try {
        const admin = await db.collection("usuarios_admin").findOne({ usuario });
        if (!admin || !verificarSenha(senha, admin.senha)) {
          return res.status(401).json({ erro: "Usuário ou senha inválidos." });
        }
        const token = gerarToken();
        sessoesAdmin.set(token, { expira: Date.now() + TOKEN_EXPIRY_MS });
        return res.json({ token });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao verificar credenciais." });
      }
    });

    app.post("/api/admin/logout", (req, res) => {
      const auth  = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (token) sessoesAdmin.delete(token);
      res.json({ ok: true });
    });

    // ─────────────────────────────────────
    // RESET DE SENHA (super-admin)
    // ─────────────────────────────────────
    app.post("/api/admin/solicitar-reset", async (req, res) => {
      const { usuario } = req.body;
      const respostaNeutra = { ok: true, mensagem: "Se o usuário existir e tiver um e-mail cadastrado, você receberá as instruções em breve." };

      if (!usuario) return res.json(respostaNeutra);

      try {
        const admin = await db.collection("usuarios_admin").findOne({ usuario });
        if (!admin || !admin.email) return res.json(respostaNeutra);

        await db.collection("tokens_reset").deleteMany({ usuarioId: admin._id, tipo: "admin" });

        const token  = gerarToken();
        const expira = new Date(Date.now() + RESET_TOKEN_EXPIRY_MS);

        await db.collection("tokens_reset").insertOne({
          token,
          usuarioId: admin._id,
          tipo:      "admin",
          expira
        });

        const baseUrl = `${req.protocol}://${req.get("host")}`;
        const link    = `${baseUrl}/reset-senha?token=${token}`;

        await transporter.sendMail({
          from:    `"Painel Soneda" <${process.env.EMAIL_USER}>`,
          to:      admin.email,
          subject: "Redefinição de senha — Administração Painel Soneda",
          html: `
            <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#0d0f14;color:#e8ecf5;border-radius:12px">
              <h2 style="font-size:1.4rem;margin-bottom:8px;color:#c8f135">Redefinição de senha</h2>
              <p style="color:#8891aa;font-size:0.9rem;margin-bottom:24px">Painel Soneda · Administração</p>
              <p style="margin-bottom:20px">Olá, <strong>${admin.usuario}</strong>.</p>
              <p style="margin-bottom:24px">Recebemos uma solicitação para redefinir a senha de administrador. Clique no botão abaixo para criar uma nova senha. O link é válido por <strong>30 minutos</strong> e pode ser usado apenas uma vez.</p>
              <a href="${link}" style="display:inline-block;background:#c8f135;color:#0d0f14;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:0.9rem;margin-bottom:24px">
                Redefinir minha senha
              </a>
              <p style="color:#5a6080;font-size:0.78rem;margin-top:24px;border-top:1px solid #252a3a;padding-top:16px">
                Se você não solicitou a redefinição de senha, ignore este e-mail.<br><br>
                Link alternativo: <a href="${link}" style="color:#c8f135">${link}</a>
              </p>
            </div>
          `
        });

        console.log(`📧 E-mail de reset admin enviado para ${admin.email}`);
        res.json(respostaNeutra);
      } catch (error) {
        console.error("❌ Erro ao enviar e-mail de reset admin:", error.code, error.message);
        res.status(500).json({
          erro:    "Erro ao enviar e-mail. Tente novamente.",
          detalhe: `[${error.code || "ERR"}] ${error.message}`
        });
      }
    });

    // ─────────────────────────────────────
    // GESTÃO DE USUÁRIOS (super-admin)
    // ─────────────────────────────────────
    app.get("/api/admin/usuarios", verificarTokenAdmin, async (req, res) => {
      try {
        const usuarios = await db
          .collection("usuarios_importacao")
          .find({}, { projection: { senha: 0 } })
          .sort({ criadoEm: 1 })
          .toArray();
        res.json(usuarios);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao listar usuários.", detalhe: error.message });
      }
    });

    app.post("/api/admin/usuarios", verificarTokenAdmin, async (req, res) => {
      const { usuario, senha, email } = req.body;
      if (!usuario || !senha) return res.status(400).json({ erro: "Usuário e senha são obrigatórios." });

      try {
        const existente = await db.collection("usuarios_importacao").findOne({ usuario });
        if (existente) return res.status(400).json({ erro: "Usuário já existe." });

        await db.collection("usuarios_importacao").insertOne({
          usuario,
          senha:    hashSenha(senha),
          email:    email ? email.trim().toLowerCase() : "",
          criadoEm: new Date()
        });
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao criar usuário.", detalhe: error.message });
      }
    });

    app.delete("/api/admin/usuarios/:id", verificarTokenAdmin, async (req, res) => {
      try {
        await db.collection("usuarios_importacao").deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao excluir usuário.", detalhe: error.message });
      }
    });

    app.put("/api/admin/usuarios/:id/senha", verificarTokenAdmin, async (req, res) => {
      const { senha } = req.body;
      if (!senha) return res.status(400).json({ erro: "Nova senha é obrigatória." });
      try {
        await db.collection("usuarios_importacao").updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { senha: hashSenha(senha) } }
        );
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao alterar senha.", detalhe: error.message });
      }
    });

    app.put("/api/admin/usuarios/:id/email", verificarTokenAdmin, async (req, res) => {
      const { email } = req.body;
      try {
        await db.collection("usuarios_importacao").updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { email: email ? email.trim().toLowerCase() : "" } }
        );
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao atualizar e-mail.", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // GESTÃO DE ADMINS (super-admin)
    // ─────────────────────────────────────
    app.get("/api/admin/admins", verificarTokenAdmin, async (req, res) => {
      try {
        const admins = await db
          .collection("usuarios_admin")
          .find({}, { projection: { senha: 0 } })
          .sort({ criadoEm: 1 })
          .toArray();
        res.json(admins);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao listar admins.", detalhe: error.message });
      }
    });

    app.post("/api/admin/admins", verificarTokenAdmin, async (req, res) => {
      const { usuario, senha, email } = req.body;
      if (!usuario || !senha) return res.status(400).json({ erro: "Usuário e senha são obrigatórios." });

      try {
        const existente = await db.collection("usuarios_admin").findOne({ usuario });
        if (existente) return res.status(400).json({ erro: "Usuário já existe." });

        await db.collection("usuarios_admin").insertOne({
          usuario,
          senha:    hashSenha(senha),
          email:    email ? email.trim().toLowerCase() : "",
          criadoEm: new Date()
        });
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao criar admin.", detalhe: error.message });
      }
    });

    app.delete("/api/admin/admins/:id", verificarTokenAdmin, async (req, res) => {
      try {
        const total = await db.collection("usuarios_admin").countDocuments();
        if (total <= 1) {
          return res.status(400).json({ erro: "Não é possível excluir o único administrador." });
        }
        await db.collection("usuarios_admin").deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao excluir admin.", detalhe: error.message });
      }
    });

    app.put("/api/admin/admins/:id/senha", verificarTokenAdmin, async (req, res) => {
      const { senha } = req.body;
      if (!senha) return res.status(400).json({ erro: "Nova senha é obrigatória." });
      try {
        await db.collection("usuarios_admin").updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { senha: hashSenha(senha) } }
        );
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao alterar senha.", detalhe: error.message });
      }
    });

    app.put("/api/admin/admins/:id/email", verificarTokenAdmin, async (req, res) => {
      const { email } = req.body;
      try {
        await db.collection("usuarios_admin").updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { email: email ? email.trim().toLowerCase() : "" } }
        );
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao atualizar e-mail.", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // CONSULTAS
    // ─────────────────────────────────────
    app.get("/api/dados-brutos", async (req, res) => {
      try {
        const limite = Number(req.query.limite || 5000);
        const dados  = await db.collection("dados_brutos").find({}).limit(limite).toArray();
        res.json(dados);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar dados brutos", detalhe: error.message });
      }
    });

    app.get("/api/lojas-depara", async (req, res) => {
      const dados = await db.collection("lojas_depara").find({}).toArray();
      res.json(dados);
    });

    app.get("/api/categorias-depara", async (req, res) => {
      const dados = await db.collection("categorias_depara").find({}).toArray();
      res.json(dados);
    });

    // ─────────────────────────────────────
    // DADOS TRATADOS (JOIN)
    // ─────────────────────────────────────
    app.get("/api/dados-tratados", async (req, res) => {
      try {
        const dados = await db.collection("dados_brutos").aggregate([
          {
            $lookup: {
              from: "categorias_depara",
              localField: "GTIN/PLU",
              foreignField: "CODBARRAS",
              as: "categoria_info"
            }
          },
          {
            $lookup: {
              from: "lojas_depara",
              localField: "Loja",
              foreignField: "Cod_Loja",
              as: "loja_info"
            }
          },
          {
            $addFields: {
              Categoria_DePara: { $arrayElemAt: ["$categoria_info.CATEGORIA", 0] },
              Familia_DePara:   { $arrayElemAt: ["$categoria_info.FAMILIA", 0] },
              Produto_DePara: {
                $arrayElemAt: [
                  {
                    $map: {
                      input: "$categoria_info",
                      as: "cat",
                      in: { $getField: { field: "NOME PRODUTO", input: "$$cat" } }
                    }
                  },
                  0
                ]
              },
              Nome_Loja_DePara: { $arrayElemAt: ["$loja_info.Nome_Fantasia", 0] }
            }
          },
          { $project: { categoria_info: 0, loja_info: 0 } }
        ]).toArray();

        res.json(dados);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar dados tratados", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // RESUMO DASHBOARD
    // ─────────────────────────────────────
    app.get("/api/dashboard/resumo", async (req, res) => {
      try {
        const pipeline = [
          {
            $group: {
              _id: null,
              total_vendido: { $sum: brToDouble({ $getField: "Venda (Qtd)" }) },
              total_valor:   { $sum: brValorExpr() },
              lojas:         { $addToSet: "$Loja" }
            }
          },
          { $project: { _id: 0, total_vendido: 1, total_valor: 1, total_lojas: { $size: "$lojas" } } }
        ];
        const resultado = await db.collection("dados_brutos").aggregate(pipeline).toArray();
        res.json(resultado[0] || { total_vendido: 0, total_valor: 0, total_lojas: 0 });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao gerar resumo", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // KPIs COM FILTRO
    // ─────────────────────────────────────
    app.get("/api/dashboard/kpis", async (req, res) => {
      try {
        const { ano, mes, loja } = req.query;
        const match = {};
        if (ano)  match["Ano"]   = String(ano);
        if (mes)  match["Mês"]   = String(mes);
        if (loja) match["Loja"]  = String(loja);

        const matchStage = Object.keys(match).length > 0 ? [{ $match: match }] : [];

        const [resumoArr, topLojaArr] = await Promise.all([
          db.collection("dados_brutos").aggregate([
            ...matchStage,
            {
              $group: {
                _id: null,
                total_vendido: { $sum: brToDouble({ $getField: "Venda (Qtd)" }) },
                total_valor:   { $sum: brValorExpr() },
                lojas:         { $addToSet: "$Loja" }
              }
            },
            { $project: { _id: 0, total_vendido: 1, total_valor: 1, total_lojas: { $size: "$lojas" } } }
          ]).toArray(),
          db.collection("dados_brutos").aggregate([
            ...matchStage,
            { $group: { _id: "$Loja", qty: { $sum: brToDouble({ $getField: "Venda (Qtd)" }) } } },
            { $sort: { qty: -1 } },
            { $limit: 1 }
          ]).toArray()
        ]);

        const resumo = resumoArr[0] || { total_vendido: 0, total_valor: 0, total_lojas: 0 };
        if (topLojaArr[0]) resumo.maior_loja = topLojaArr[0];

        res.json(resumo);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao gerar KPIs", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // AGREGADOS DASHBOARD (qtd + valor, por loja / cat / fam / dia)
    // ─────────────────────────────────────
    app.get("/api/dashboard/agregados", async (req, res) => {
      try {
        const { ano, mes, loja, cat, familia } = req.query;
        const aLoja    = req.query.ativo_loja    || null;
        const aCat     = req.query.ativo_cat     || null;
        const aFamilia = req.query.ativo_familia || null;

        const joinCat = [
          { $lookup: { from: "categorias_depara", localField: "GTIN/PLU", foreignField: "CODBARRAS", as: "_c" } },
          { $addFields: { _cat: { $arrayElemAt: ["$_c.CATEGORIA", 0] }, _fam: { $arrayElemAt: ["$_c.FAMILIA", 0] } } }
        ];

        const grp = {
          qty:   { $sum: brToDouble({ $getField: "Venda (Qtd)" }) },
          valor: { $sum: brValorExpr() }
        };

        function baseStages(opt = {}) {
          const s = [];
          const m = {};
          if (ano) m["Ano"] = String(ano);
          if (mes) m["Mês"] = String(mes);
          if (loja)                    m["Loja"] = String(loja);
          if (aLoja && !opt.noActLoja) m["Loja"] = String(aLoja);
          if (Object.keys(m).length)   s.push({ $match: m });

          const cf = [];
          if (cat)                       cf.push({ $match: { _cat: cat } });
          if (familia)                   cf.push({ $match: { _fam: familia } });
          if (aCat    && !opt.noActCat)  cf.push({ $match: { _cat: aCat } });
          if (aFamilia && !opt.noActFam) cf.push({ $match: { _fam: aFamilia } });

          if (cf.length || opt.needsJoin) s.push(...joinCat, ...cf);
          return s;
        }

        // Skip category/family lookup when no filters active and categorias_depara is empty
        const needsCatLookup = !!(cat || familia || aCat || aFamilia);
        const catCount = needsCatLookup ? 1 :
          await db.collection("categorias_depara").estimatedDocumentCount();

        const AGG_OPTS = { allowDiskUse: true };

        const [por_loja, catFamResult, por_dia] = await Promise.all([
          db.collection("dados_brutos").aggregate([
            ...baseStages({ noActLoja: true }),
            { $group: { _id: "$Loja", ...grp } },
            { $sort: { qty: -1 } }
          ], AGG_OPTS).toArray(),

          catCount > 0 ? Promise.all([
            db.collection("dados_brutos").aggregate([
              ...baseStages({ noActCat: true, needsJoin: true }),
              { $group: { _id: "$_cat", ...grp } },
              { $match: { _id: { $ne: null } } },
              { $sort: { qty: -1 } }
            ], AGG_OPTS).toArray(),
            db.collection("dados_brutos").aggregate([
              ...baseStages({ noActFam: true, needsJoin: true }),
              { $group: { _id: "$_fam", ...grp } },
              { $match: { _id: { $ne: null } } },
              { $sort: { qty: -1 } }
            ], AGG_OPTS).toArray()
          ]) : Promise.resolve([[], []]),

          db.collection("dados_brutos").aggregate([
            ...baseStages({}),
            { $group: { _id: "$Data", ...grp } },
            { $sort: { _id: 1 } }
          ], AGG_OPTS).toArray()
        ]);

        const [por_cat, por_fam] = catFamResult;

        res.json({
          por_loja: por_loja.map(r => ({ loja: r._id, qty: r.qty, valor: r.valor })),
          por_cat:  por_cat.map(r  => ({ cat:  r._id || "SEM CATEGORIA", qty: r.qty, valor: r.valor })),
          por_fam:  por_fam.map(r  => ({ fam:  r._id || "SEM FAMÍLIA",   qty: r.qty, valor: r.valor })),
          por_dia:  por_dia.map(r  => ({ data: r._id, qty: r.qty, valor: r.valor }))
        });
      } catch(e) {
        res.status(500).json({ erro: "Erro ao agregar dados", detalhe: e.message });
      }
    });

    // ─────────────────────────────────────
    // VENDAS POR FILIAL
    // ─────────────────────────────────────
    app.get("/api/dashboard/vendas-por-filial", async (req, res) => {
      try {
        const resultado = await db.collection("dados_brutos").aggregate([
          {
            $group: {
              _id: "$Loja",
              total_venda: { $sum: brValorExpr() }
            }
          },
          { $sort: { total_venda: -1 } },
          { $limit: 20 }
        ]).toArray();
        res.json(resultado);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar vendas por filial", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // CATEGORIAS
    // ─────────────────────────────────────
    app.get("/api/dashboard/categorias", async (req, res) => {
      try {
        const resultado = await db.collection("categorias_depara").aggregate([
          { $group: { _id: "$CATEGORIA", total: { $sum: 1 } } },
          { $sort: { total: -1 } }
        ]).toArray();
        res.json(resultado);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar categorias", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // FAMÍLIAS
    // ─────────────────────────────────────
    app.get("/api/dashboard/familias", async (req, res) => {
      try {
        const resultado = await db.collection("categorias_depara").aggregate([
          { $group: { _id: "$FAMILIA", total: { $sum: 1 } } },
          { $sort: { total: -1 } }
        ]).toArray();
        res.json(resultado);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar famílias", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // VENDAS POR DIA
    // ─────────────────────────────────────
    app.get("/api/dashboard/vendas-por-dia", async (req, res) => {
      try {
        const resultado = await db.collection("dados_brutos").aggregate([
          {
            $group: {
              _id: { ano: "$Ano", mes: "$Mês" },
              total_venda: { $sum: brValorExpr() }
            }
          },
          { $sort: { "_id.ano": 1, "_id.mes": 1 } }
        ]).toArray();
        res.json(resultado);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar vendas por dia", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // IMPORTAÇÕES (PROTEGIDAS) — suporte a upload chunked
    // ─────────────────────────────────────

    // Helper: processa um arquivo CSV temporário e insere na coleção
    async function processarChunkCSV(req, colecao, limparColunas, opcoes = {}) {
      return new Promise((resolve, reject) => {
        const resultados = [];
        const stream = fs.createReadStream(req.file.path).pipe(csv({ separator: ";" }));

        stream.on("data", (linha) => {
          const registro = {};
          Object.keys(linha).forEach((coluna) => {
            const k    = limparColunas ? coluna.trim() : limparValor(coluna);
            const rawV = limparColunas ? linha[coluna].trim() : limparValor(linha[coluna]);
            registro[k] = parseBRNumber(rawV);
          });
          if (opcoes.extraCampos) Object.assign(registro, opcoes.extraCampos);
          resultados.push(registro);
        });

        stream.on("error", reject);

        stream.on("end", async () => {
          try {
            if (opcoes.deleteFirst) await colecao.deleteMany({});
            if (resultados.length > 0) {
              await colecao.insertMany(resultados, { ordered: false });
            }
            try { fs.unlinkSync(req.file.path); } catch (_) {}
            resolve(resultados.length);
          } catch (err) {
            try { fs.unlinkSync(req.file.path); } catch (_) {}
            reject(err);
          }
        });
      });
    }

    app.post("/api/importar/dados-brutos", verificarToken, upload.single("file"), async (req, res) => {
      if (!req.file) return res.status(400).json({ erro: "Nenhum arquivo enviado." });

      const importId     = req.body.importId    || crypto.randomBytes(8).toString("hex");
      const chunkIndex   = parseInt(req.body.chunkIndex   ?? "0",  10);
      const totalChunks  = parseInt(req.body.totalChunks  ?? "1",  10);
      const totalRecords = parseInt(req.body.totalRecords ?? "0",  10);
      const nomeArquivo  = req.file.originalname || req.file.filename;

      try {
        const inserido = await processarChunkCSV(req, db.collection("dados_brutos"), false, {
          extraCampos: { importado_em: new Date(), _import_id: importId }
        });

        const isUltimo = chunkIndex === totalChunks - 1;
        if (isUltimo) {
          await db.collection("logs_importacao").insertOne({
            importId, tipo: "dados_brutos", arquivo: nomeArquivo,
            usuario: req.usuarioLogado, total: totalRecords || inserido, data: new Date()
          });
        }

        res.json({
          ok: true,
          inserido,
          ultimo: isUltimo,
          mensagem: isUltimo ? "Importação finalizada 🚀" : "Lote salvo"
        });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao salvar no banco de dados", detalhe: error.message });
      }
    });

    app.post("/api/importar/categorias-depara", verificarToken, upload.single("file"), async (req, res) => {
      if (!req.file) return res.status(400).json({ erro: "Nenhum arquivo enviado." });

      const importId     = req.body.importId    || crypto.randomBytes(8).toString("hex");
      const chunkIndex   = parseInt(req.body.chunkIndex   ?? "0", 10);
      const totalChunks  = parseInt(req.body.totalChunks  ?? "1", 10);
      const totalRecords = parseInt(req.body.totalRecords ?? "0", 10);
      const nomeArquivo  = req.file.originalname || req.file.filename;

      try {
        const inserido = await processarChunkCSV(req, db.collection("categorias_depara"), true, {
          deleteFirst: chunkIndex === 0,
          extraCampos: { _import_id: importId }
        });

        const isUltimo = chunkIndex === totalChunks - 1;
        if (isUltimo) {
          await db.collection("logs_importacao").insertOne({
            importId, tipo: "categorias_depara", arquivo: nomeArquivo,
            usuario: req.usuarioLogado, total: totalRecords || inserido, data: new Date()
          });
        }

        res.json({ ok: true, inserido, ultimo: isUltimo, mensagem: isUltimo ? "Categorias importadas" : "Lote salvo" });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao salvar no banco de dados", detalhe: error.message });
      }
    });

    app.post("/api/importar/lojas-depara", verificarToken, upload.single("file"), async (req, res) => {
      if (!req.file) return res.status(400).json({ erro: "Nenhum arquivo enviado." });

      const importId     = req.body.importId    || crypto.randomBytes(8).toString("hex");
      const chunkIndex   = parseInt(req.body.chunkIndex   ?? "0", 10);
      const totalChunks  = parseInt(req.body.totalChunks  ?? "1", 10);
      const totalRecords = parseInt(req.body.totalRecords ?? "0", 10);
      const nomeArquivo  = req.file.originalname || req.file.filename;

      try {
        const inserido = await processarChunkCSV(req, db.collection("lojas_depara"), true, {
          deleteFirst: chunkIndex === 0,
          extraCampos: { _import_id: importId }
        });

        const isUltimo = chunkIndex === totalChunks - 1;
        if (isUltimo) {
          await db.collection("logs_importacao").insertOne({
            importId, tipo: "lojas_depara", arquivo: nomeArquivo,
            usuario: req.usuarioLogado, total: totalRecords || inserido, data: new Date()
          });
        }

        res.json({ ok: true, inserido, ultimo: isUltimo, mensagem: isUltimo ? "Lojas importadas" : "Lote salvo" });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao salvar no banco de dados", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // LOGS DE IMPORTAÇÃO (admin)
    // ─────────────────────────────────────
    app.get("/api/admin/logs-importacao", verificarTokenAdmin, async (req, res) => {
      try {
        const logs = await db.collection("logs_importacao")
          .find({})
          .sort({ data: -1 })
          .limit(500)
          .toArray();
        res.json(logs);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao listar logs.", detalhe: error.message });
      }
    });

    app.delete("/api/admin/logs-importacao/:id", verificarTokenAdmin, async (req, res) => {
      try {
        const log = await db.collection("logs_importacao").findOne({ _id: new ObjectId(req.params.id) });
        if (!log) return res.status(404).json({ erro: "Log não encontrado." });

        if (log.tipo === "dados_brutos") {
          await db.collection("dados_brutos").deleteMany({ _import_id: log.importId });
        } else if (log.tipo === "categorias_depara") {
          await db.collection("categorias_depara").deleteMany({});
        } else if (log.tipo === "lojas_depara") {
          await db.collection("lojas_depara").deleteMany({});
        }

        await db.collection("logs_importacao").deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao desfazer importação.", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    const server = app.listen(PORT, () => {
      console.log(`🚀 Servidor rodando na porta ${PORT}`);
    });
    // Aumenta timeout para suportar imports de arquivos grandes
    server.timeout        = 10 * 60 * 1000; // 10 minutos
    server.keepAliveTimeout = 10 * 60 * 1000;

  } catch (erro) {
    console.error("❌ Erro ao iniciar servidor:", erro);
  }
}

iniciarServidor();
