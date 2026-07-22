const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const multer = require("multer");
const csv = require("csv-parser");
const XLSX = require("xlsx");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));
const frontendPath = path.resolve(__dirname, "../../frontend");

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.use(express.static(frontendPath));

const PORT = process.env.PORT || 3000;
const uri = process.env.MONGODB_URI;
const dbName = process.env.DB_NAME || "soneda_dashboard";
const READ_ONLY = /^(1|true|yes|sim)$/i.test(process.env.READ_ONLY || "");
const USUARIO_PAI_PADRAO = "larissa antunez";

const client = new MongoClient(uri);

const WRITE_METHODS = new Set([
  "bulkWrite",
  "createIndex",
  "createIndexes",
  "deleteMany",
  "deleteOne",
  "drop",
  "dropIndex",
  "dropIndexes",
  "findOneAndDelete",
  "findOneAndReplace",
  "findOneAndUpdate",
  "insertMany",
  "insertOne",
  "replaceOne",
  "updateMany",
  "updateOne"
]);

function pipelineTemEscrita(pipeline = []) {
  return Array.isArray(pipeline) && pipeline.some(stage => stage && (stage.$merge || stage.$out));
}

function bloquearEscritaMongo(operacao) {
  const erro = new Error(`Ambiente somente leitura: operacao Mongo bloqueada (${operacao}).`);
  erro.code = "READ_ONLY_MONGO_WRITE_BLOCKED";
  throw erro;
}

function criarDbSomenteLeitura(db) {
  return new Proxy(db, {
    get(target, prop) {
      if (prop === "collection") {
        return (nome, ...args) => {
          const collection = target.collection(nome, ...args);
          return new Proxy(collection, {
            get(colTarget, colProp) {
              if (WRITE_METHODS.has(colProp)) {
                return () => bloquearEscritaMongo(`${String(nome)}.${String(colProp)}`);
              }
              if (colProp === "aggregate") {
                return (pipeline, options) => {
                  if (pipelineTemEscrita(pipeline)) {
                    bloquearEscritaMongo(`${String(nome)}.aggregate($merge/$out)`);
                  }
                  return colTarget.aggregate(pipeline, options);
                };
              }
              const value = colTarget[colProp];
              return typeof value === "function" ? value.bind(colTarget) : value;
            }
          });
        };
      }
      const value = target[prop];
      return typeof value === "function" ? value.bind(target) : value;
    }
  });
}

app.use((req, res, next) => {
  if (!READ_ONLY) return next();
  const metodoEscrita = ["POST", "PUT", "PATCH", "DELETE"].includes(req.method);
  const rotaSessao = [
    "/api/login",
    "/api/logout",
    "/api/admin/login",
    "/api/admin/logout"
  ].includes(req.path);
  if (metodoEscrita && !rotaSessao) {
    return res.status(403).json({
      erro: "Ambiente de testes em modo somente leitura. Alteracoes foram bloqueadas."
    });
  }
  next();
});

// ── CACHE DE RESULTADOS (TTL 60 min) ─────────────────────────────────────────
const _cache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000;
let _dadosVersionCache = { ts: 0, value: "init" };
function cacheGet(k) {
  const e = _cache.get(k);
  if (!e) return null;
  if (Date.now() - e.ts > CACHE_TTL_MS) { _cache.delete(k); return null; }
  return e.data;
}
function cacheSet(k, d) { _cache.set(k, { data: d, ts: Date.now() }); }
function cacheClear() {
  _cache.clear();
  _dadosVersionCache = { ts: 0, value: "init" };
}

// ── FLAGS DE OTIMIZAÇÃO ──────────────────────────────────────────────────────
let _migNumericos = false; // true quando dados têm _qtd_num/_valor_num pré-computados
let _migGtin      = false; // true quando dados têm _gtin pré-computado (join indexado)
let _migData      = false; // true quando dados têm _data_iso pré-computado (filtro de data indexado)
let _migCat       = false; // true quando dados têm _cat/_fam pré-computados (elimina $lookup em queries)
let _catCountCache = -1;   // cache em memória do estimatedDocumentCount de categorias_depara

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

function normalizarUsuario(usuario) {
  return String(usuario || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .trim()
    .toLowerCase()
    .replace(/[_\s]+/g, " ");
}

async function obterUsuarioPai(db) {
  return db.collection("usuarios_admin").findOne({ usuarioPai: true });
}

async function garantirUsuarioPai(db) {
  const admins = await db.collection("usuarios_admin").find({}).sort({ criadoEm: 1 }).toArray();
  if (!admins.length) return null;

  const pais = admins.filter(a => a.usuarioPai === true);
  if (pais.length) {
    if (pais.length > 1) {
      await db.collection("usuarios_admin").updateMany(
        { _id: { $in: pais.slice(1).map(a => a._id) } },
        { $unset: { usuarioPai: "" } }
      );
    }
    return pais[0];
  }

  const adminPai = admins.find(a => normalizarUsuario(a.usuario) === USUARIO_PAI_PADRAO)
    || admins.find(a => normalizarUsuario(a.usuario) === normalizarUsuario(process.env.ADMIN_USER))
    || admins[0];

  await db.collection("usuarios_admin").updateOne(
    { _id: adminPai._id },
    { $set: { usuarioPai: true } }
  );
  return { ...adminPai, usuarioPai: true };
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

function limparTextoExibicao(valor) {
  return String(valor ?? "")
    .replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200D\uFEFF\uFFFD]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function parseBRNumber(val) {
  if (val === undefined || val === null || val === "") return val;
  if (typeof val === "number") return val;
  let s = String(val).trim().replace(/^R\$\s*/i, '').replace(/\s/g, '');
  if (!s) return val;
  let sign = 1;
  if (/^\(.*\)$/.test(s)) { sign = -1; s = s.slice(1, -1); }
  if (s.startsWith('-')) { sign = -1; s = s.slice(1); }
  if (/^\d{1,3}(?:\.\d{3})+,\d+$/.test(s)) return sign * parseFloat(s.replace(/\./g, '').replace(',', '.'));
  if (/^\d+,\d+$/.test(s)) return sign * parseFloat(s.replace(',', '.'));
  if (/^\d{1,3}(?:\.\d{3})+$/.test(s)) return sign * parseFloat(s.replace(/\./g, ''));
  if (/^\d+\.\d+$/.test(s)) return sign * parseFloat(s);
  return val;
}

// Normaliza código de barras: trata notação científica do Excel (ex: "7,891E+12" → "7891000000000")
function normalizarEAN(val) {
  let s = String(val ?? '').trim().replace(/^["']|["']$/g, '');
  // Notação científica BR: "7,891E+12" → "7.891E+12"
  s = s.replace(/^(\d+),(\d*[eE])/i, '$1.$2');
  // Notação científica: "7.891E+12" → número inteiro
  if (/^\d+\.?\d*[eE][+\-]?\d+$/i.test(s)) s = String(Math.round(Number(s)));
  // Remove zeros decimais e caracteres não-numéricos
  s = s.replace(/\.0+$/, '').replace(/[^\d]/g, '');
  return s || String(val ?? '').trim();
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
  const noSpaces = {
    $replaceAll: {
      input: { $replaceAll: { input: { $trim: { input: noPrefix } }, find: " ", replacement: "" } },
      find: " ", replacement: ""
    }
  };
  const normalized = {
    $switch: {
      branches: [
        {
          case: { $regexMatch: { input: noSpaces, regex: /^-?\d{1,3}(?:\.\d{3})+,\d+$/ } },
          then: { $replaceAll: { input: { $replaceAll: { input: noSpaces, find: ".", replacement: "" } }, find: ",", replacement: "." } }
        },
        {
          case: { $regexMatch: { input: noSpaces, regex: /^-?\d+,\d+$/ } },
          then: { $replaceAll: { input: noSpaces, find: ",", replacement: "." } }
        },
        {
          case: { $regexMatch: { input: noSpaces, regex: /^-?\d{1,3}(?:\.\d{3})+$/ } },
          then: { $replaceAll: { input: noSpaces, find: ".", replacement: "" } }
        }
      ],
      default: noSpaces
    }
  };
  return {
    $convert: {
      input: normalized,
      to: "double", onError: 0, onNull: 0
    }
  };
}

// Valor oficial de venda: usar somente a coluna bruta "Venda (R$)".
function brValorExpr() {
  return brToDouble({ $getField: "Venda (R$)" });
}

function matchTextoOuNumero(valor) {
  const s = String(valor);
  const n = Number(s);
  return Number.isFinite(n) && s.trim() !== "" ? { $in: [s, n] } : s;
}

const MESES_ABREV = ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"];

function normalizarMes(valor) {
  const raw = String(valor ?? "").trim();
  if (!raw) return "";
  const numero = Number(raw);
  if (Number.isInteger(numero) && numero >= 1 && numero <= 12) return MESES_ABREV[numero - 1];
  const semAcento = raw.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
  const mapa = {
    jan: "Jan", janeiro: "Jan",
    fev: "Fev", fevereiro: "Fev",
    mar: "Mar", marco: "Mar", marcoo: "Mar",
    abr: "Abr", abril: "Abr",
    mai: "Mai", maio: "Mai",
    jun: "Jun", junho: "Jun",
    jul: "Jul", julho: "Jul",
    ago: "Ago", agosto: "Ago",
    set: "Set", setembro: "Set",
    out: "Out", outubro: "Out",
    nov: "Nov", novembro: "Nov",
    dez: "Dez", dezembro: "Dez"
  };
  return mapa[semAcento.slice(0, 3)] || mapa[semAcento] || raw;
}

function mesDeData(valor) {
  const dataStr = String(valor ?? "").trim();
  const brMatch = dataStr.match(/^\d{1,2}\/(\d{1,2})\/\d{4}$/);
  const isoMatch = dataStr.match(/^\d{4}-(\d{2})-\d{2}$/);
  const mesNum = brMatch ? Number(brMatch[1]) : (isoMatch ? Number(isoMatch[1]) : 0);
  return mesNum >= 1 && mesNum <= 12 ? MESES_ABREV[mesNum - 1] : "";
}

function listaParam(valor) {
  const base = Array.isArray(valor) ? valor : String(valor ?? "").split(",");
  return base.map(v => String(v ?? "").trim()).filter(Boolean);
}

function matchTextoOuNumeroLista(valores) {
  const itens = [];
  listaParam(valores).forEach(valor => {
    itens.push(valor);
    const numero = Number(valor);
    if (!Number.isNaN(numero)) itens.push(numero);
  });
  const unicos = [...new Set(itens)];
  if (!unicos.length) return null;
  return unicos.length === 1 ? unicos[0] : { $in: unicos };
}

function aplicarFiltroAno(match, ano) {
  const criterio = matchTextoOuNumeroLista(ano);
  if (criterio !== null) match["Ano"] = criterio;
}

function matchListaTexto(valor) {
  const valores = listaParam(valor);
  if (!valores.length) return null;
  return valores.length === 1 ? valores[0] : { $in: valores };
}

function produtoNomeExpr() {
  return {
    $ifNull: [
      { $getField: "Produto" },
      { $ifNull: [
        { $getField: "produto" },
        { $ifNull: [
          { $getField: "Descrição" },
          { $getField: "DescriÃ§Ã£o" }
        ] }
      ] }
    ]
  };
}

function produtoDeParaExpr(fallbackExpr = produtoNomeExpr()) {
  return {
    $ifNull: [
      { $arrayElemAt: ["$_c.Produto", 0] },
      { $ifNull: [
        { $arrayElemAt: ["$_c.PRODUTO", 0] },
        { $ifNull: [
          { $arrayElemAt: ["$_c.NOME PRODUTO", 0] },
          { $ifNull: [
            { $arrayElemAt: ["$_c.NOME_PRODUTO", 0] },
            { $ifNull: [
              { $arrayElemAt: ["$_c.Descrição", 0] },
              { $ifNull: [
                { $arrayElemAt: ["$_c.DESCRICAO", 0] },
                fallbackExpr
              ] }
            ] }
          ] }
        ] }
      ] }
    ]
  };
}

function aplicarFiltroMes(match, mes) {
  const meses = listaParam(mes)
    .map(normalizarMes)
    .filter(Boolean);
  if (!meses.length) return;

  const opcoes = [];
  meses.forEach(mesAbrev => {
    const mesNum = MESES_ABREV.indexOf(mesAbrev) + 1;
    if (mesNum <= 0) return;
    opcoes.push(
      { "Mês": mesAbrev },
      { "Mes": mesAbrev },
      { "Mês": String(mesNum) },
      { "Mes": String(mesNum) },
      { "Mês": mesNum },
      { "Mes": mesNum }
    );
  });
  if (opcoes.length) match.$or = opcoes;
}

function mesNumeroExpr() {
  const mesRaw = { $toString: { $ifNull: [{ $getField: "Mês" }, { $getField: "Mes" }] } };
  return {
    $switch: {
      branches: [
        { case: { $in: [mesRaw, ["1", "01", "Jan", "jan"]] }, then: "01" },
        { case: { $in: [mesRaw, ["2", "02", "Fev", "fev"]] }, then: "02" },
        { case: { $in: [mesRaw, ["3", "03", "Mar", "mar"]] }, then: "03" },
        { case: { $in: [mesRaw, ["4", "04", "Abr", "abr"]] }, then: "04" },
        { case: { $in: [mesRaw, ["5", "05", "Mai", "mai"]] }, then: "05" },
        { case: { $in: [mesRaw, ["6", "06", "Jun", "jun"]] }, then: "06" },
        { case: { $in: [mesRaw, ["7", "07", "Jul", "jul"]] }, then: "07" },
        { case: { $in: [mesRaw, ["8", "08", "Ago", "ago"]] }, then: "08" },
        { case: { $in: [mesRaw, ["9", "09", "Set", "set"]] }, then: "09" },
        { case: { $in: [mesRaw, ["10", "Out", "out"]] }, then: "10" },
        { case: { $in: [mesRaw, ["11", "Nov", "nov"]] }, then: "11" },
        { case: { $in: [mesRaw, ["12", "Dez", "dez"]] }, then: "12" }
      ],
      default: "00"
    }
  };
}

function anoValidoOuFallbackExpr(anoFallback = null) {
  const anoRaw = { $toString: { $ifNull: ["$Ano", ""] } };
  const fallback = anoFallback ? String(anoFallback) : null;
  return {
    $cond: [
      { $regexMatch: { input: anoRaw, regex: /^(19|20)\d{2}$/ } },
      anoRaw,
      fallback
    ]
  };
}

function dataFallbackPorMesExpr(anoFallback = null) {
  return {
    $let: {
      vars: {
        ano: anoValidoOuFallbackExpr(anoFallback),
        mes: mesNumeroExpr()
      },
      in: {
        $cond: [
          {
            $and: [
              { $regexMatch: { input: "$$ano", regex: /^(19|20)\d{2}$/ } },
              { $ne: ["$$mes", "00"] }
            ]
          },
          { $concat: ["$$ano", "-", "$$mes", "-01"] },
          null
        ]
      }
    }
  };
}

function dataIsoValidaExpr() {
  const iso = { $toString: { $ifNull: ["$_data_iso", ""] } };
  return {
    $cond: [
      { $regexMatch: { input: iso, regex: /^(19|20)\d{2}-\d{2}-\d{2}$/ } },
      "$_data_iso",
      null
    ]
  };
}

function dataValidaPorCampoDataExpr() {
  const dataFormatada = {
    $dateToString: {
      format: "%Y-%m-%d",
      date: {
        $ifNull: [
          { $dateFromString: { dateString: { $toString: { $ifNull: [{ $getField: "Data" }, ""] } }, format: "%d/%m/%Y", onError: null, onNull: null } },
          { $dateFromString: { dateString: { $toString: { $ifNull: [{ $getField: "Data" }, ""] } }, format: "%Y-%m-%d", onError: null, onNull: null } }
        ]
      },
      onNull: null
    }
  };
  return {
    $let: {
      vars: { data: dataFormatada },
      in: {
        $cond: [
          { $regexMatch: { input: { $toString: { $ifNull: ["$$data", ""] } }, regex: /^(19|20)\d{2}-\d{2}-\d{2}$/ } },
          "$$data",
          null
        ]
      }
    }
  };
}

function mesAbrevPorIsoExpr() {
  const mesIso = { $substr: ["$_data_iso", 5, 2] };
  return {
    $switch: {
      branches: MESES_ABREV.map((nome, idx) => ({
        case: { $eq: [mesIso, String(idx + 1).padStart(2, "0")] },
        then: nome
      })),
      default: { $ifNull: [{ $getField: "Mês" }, { $getField: "Mes" }] }
    }
  };
}

function filtroMesDivergente() {
  return {
    _data_iso: { $type: "string", $regex: /^\d{4}-\d{2}-\d{2}$/ },
    $expr: { $ne: [{ $getField: "Mês" }, mesAbrevPorIsoExpr()] }
  };
}

// ─────────────────────────────────────────
// SERVIDOR
// ─────────────────────────────────────────
async function iniciarServidor() {
  try {
    await client.connect();
    const db = READ_ONLY ? criarDbSomenteLeitura(client.db(dbName)) : client.db(dbName);

    async function dadosVersion() {
      if (Date.now() - _dadosVersionCache.ts < 5000) return _dadosVersionCache.value;
      const [total, ultimoLog] = await Promise.all([
        db.collection("dados_brutos").countDocuments({}),
        db.collection("logs_importacao")
          .find({ tipo: "dados_brutos" }, { projection: { importId: 1, data: 1 } })
          .sort({ data: -1 })
          .limit(1)
          .next()
      ]);
      const logKey = ultimoLog ? `${ultimoLog.importId || ""}:${ultimoLog.data ? new Date(ultimoLog.data).getTime() : ""}` : "sem-log";
      _dadosVersionCache = { ts: Date.now(), value: `${total}:${logKey}` };
      return _dadosVersionCache.value;
    }

    async function dashboardCacheKey(prefix, query) {
      return `${prefix}:${await dadosVersion()}:${JSON.stringify(query)}`;
    }

    async function mapaNomesLojas() {
      const rows = await db.collection("lojas_depara")
        .find({}, { projection: { Cod_Loja: 1, Nome_Fantasia: 1 } })
        .toArray();
      const map = new Map();
      rows.forEach(r => {
        const raw = String(r.Cod_Loja ?? "").trim();
        const norm = normalizarCodigoLoja(raw);
        const nome = limparTextoExibicao(r.Nome_Fantasia);
        if (!raw || !nome) return;
        map.set(raw, nome);
        if (norm) {
          map.set(norm, nome);
          if (/^\d+$/.test(norm)) map.set(norm.padStart(2, "0"), nome);
        }
      });
      return map;
    }

    function normalizarCodigoLoja(valor) {
      const raw = String(valor ?? "").trim();
      const num = parseInt(raw, 10);
      return Number.isNaN(num) ? raw : String(num);
    }

    function nomeLojaPorCodigo(codigo, map) {
      const raw = String(codigo ?? "").trim();
      const norm = normalizarCodigoLoja(raw);
      const padded = /^\d+$/.test(norm) ? norm.padStart(2, "0") : norm;
      return map.get(raw) || map.get(norm) || map.get(padded) || `Filial ${norm || raw}`;
    }

    async function anoReferenciaMensal(anoParam = null) {
      const anosParam = listaParam(anoParam)
        .map(v => Number(String(v).trim()))
        .filter(v => Number.isInteger(v) && v >= 1900 && v <= 2099);
      if (anosParam.length === 1) return anosParam[0];

      const anos = await db.collection("dados_brutos").distinct("Ano");
      return anos
        .map(v => Number(String(v ?? "").trim()))
        .filter(v => Number.isInteger(v) && v >= 1900 && v <= 2099)
        .sort((a, b) => b - a)[0] || null;
    }

    console.log("✅ Conectado ao MongoDB");
    console.log(`📦 Banco em uso: ${dbName}`);

    // ── FUNÇÕES DE OTIMIZAÇÃO ────────────────────────────────────────────────
    async function atualizarFlagsMigracao() {
      const catPendente = { _cat: { $exists: false } };
      const [s1, s2, s3, s4] = await Promise.all([
        db.collection("dados_brutos").findOne({ _qtd_num:  { $exists: true } }, { projection: { _id: 1 } }),
        db.collection("dados_brutos").findOne({ _gtin:     { $exists: true } }, { projection: { _id: 1 } }),
        db.collection("dados_brutos").findOne({ _data_iso: { $exists: true } }, { projection: { _id: 1 } }),
        db.collection("dados_brutos").findOne(catPendente, { projection: { _id: 1 } })
      ]);
      _migNumericos = !!s1;
      _migGtin      = !!s2;
      _migData      = !!s3;
      _migCat       = !s4;
      _catCountCache = -1; // força re-leitura do catCount
      console.log(`📊 Otimizações ativas: numéricos=${_migNumericos}, gtin=${_migGtin}, data=${_migData}, cat=${_migCat}`);
    }

    // Migração automática de campos de performance (roda inteiramente no MongoDB, não bloqueia Node.js)
    async function migrarCamposBackground() {
      try {
        const [rNum, rGtin, rData] = await Promise.all([
          db.collection("dados_brutos").updateMany(
            { $or: [{ _qtd_num: { $exists: false } }, { _valor_num: { $exists: false } }, { _estoque_num: { $exists: false } }] },
            [{ $set: {
              _qtd_num: brToDouble({ $getField: "Venda (Qtd)" }),
              _valor_num: brValorExpr(),
              _estoque_num: brToDouble({ $getField: "Estoque Diario" })
            } }]
          ),
          db.collection("dados_brutos").updateMany(
            { _gtin: { $exists: false } },
            [{ $set: { _gtin: { $toString: { $ifNull: [{ $getField: "GTIN/PLU" }, ""] } } } }]
          ),
          // Converte Data (DD/MM/YYYY ou YYYY-MM-DD) para string ISO YYYY-MM-DD (ordenável)
          // Inclui registros onde _data_iso=null mas Data existe (migração antiga que não reconheceu o formato)
          db.collection("dados_brutos").updateMany(
            { $and: [{ $or: [{ _data_iso: { $exists: false } }, { _data_iso: null }] }, { Data: { $exists: true, $ne: "" } }] },
            [{ $set: {
              _data_iso: {
                $let: {
                  vars: { d: { $toString: { $ifNull: [{ $getField: "Data" }, ""] } } },
                  in: {
                    $dateToString: {
                      date: { $ifNull: [
                        { $dateFromString: { dateString: "$$d", format: "%d/%m/%Y", onError: null, onNull: null } },
                        { $dateFromString: { dateString: "$$d", format: "%Y-%m-%d", onError: null, onNull: null } }
                      ]},
                      format: "%Y-%m-%d",
                      onNull: null
                    }
                  }
                }
              }
            }}]
          )
        ]);
        const rMes = await db.collection("dados_brutos").updateMany(
          filtroMesDivergente(),
          [{ $set: { "Mês": mesAbrevPorIsoExpr() } }]
        );
        if (rNum.modifiedCount > 0)  { _migNumericos = true; }
        if (rGtin.modifiedCount > 0) { _migGtin      = true; }
        if (rData.modifiedCount > 0) { _migData      = true; }
        if (rNum.modifiedCount > 0 || rGtin.modifiedCount > 0 || rData.modifiedCount > 0 || rMes.modifiedCount > 0) {
          cacheClear();
          console.log(`✅ Auto-migração: ${rNum.modifiedCount} numéricos, ${rGtin.modifiedCount} gtin, ${rData.modifiedCount} data_iso, ${rMes.modifiedCount} meses`);
        }

        // Pré-computa _cat/_fam via $merge — elimina o $lookup caro em cada query
        if (!_migCat) {
          const catCnt = await db.collection("categorias_depara").estimatedDocumentCount();
          _catCountCache = catCnt;
          if (catCnt > 0) {
            const catPendente = { _cat: { $exists: false } };
            const semCat = await db.collection("dados_brutos").countDocuments(catPendente);
            if (semCat > 0) {
              await db.collection("dados_brutos").aggregate([
                { $match: catPendente },
                { $set: { _gtin_lookup: { $toString: { $ifNull: ["$_gtin", { $getField: "GTIN/PLU" }] } } } },
                { $lookup: {
                    from: "categorias_depara",
                    localField: "_gtin_lookup",
                    foreignField: "CODBARRAS",
                    as: "_cjoin"
                }},
                { $set: {
                    _cat: { $arrayElemAt: ["$_cjoin.CATEGORIA", 0] },
                    _fam: { $arrayElemAt: ["$_cjoin.FAMILIA", 0] }
                }},
                { $unset: ["_cjoin", "_gtin_lookup"] },
                { $merge: { into: "dados_brutos", whenMatched: "merge", whenNotMatched: "discard" } }
              ], { allowDiskUse: true }).toArray();
              _migCat = true;
              cacheClear();
              console.log(`✅ Auto-migração: _cat/_fam pré-computados em ${semCat} documentos`);
              await Promise.all([
                db.collection("dados_brutos").createIndex({ _cat: 1 }),
                db.collection("dados_brutos").createIndex({ _fam: 1 })
              ]);
            } else {
              _migCat = true; // todos já têm _cat
            }
          }
        }
      } catch(e) {
        console.warn('⚠️ Auto-migração em background falhou:', e.message);
      }
    }

    await atualizarFlagsMigracao();
    // Migra campos de performance em background sem bloquear o startup
    if (!READ_ONLY) migrarCamposBackground();
    function aquecerCacheDashboard(motivo = "startup") {
      const { request } = require('http');
      const PORT_WU = process.env.PORT || 3000;
      const anoAtual = new Date().getFullYear();
      const paths = [
        `/api/dashboard/agregados?ano=${anoAtual}&escopo=loja`,
        `/api/dashboard/agregados?ano=${anoAtual}`,
        `/api/dashboard/estoque-resumo?ano=${anoAtual}`
      ];
      paths.forEach(pathReq => {
        const req = request({ hostname: 'localhost', port: PORT_WU, path: pathReq }, res => {
          res.resume();
          console.log(`Cache pre-aquecido (${motivo}): ${pathReq}`);
        });
        req.on('error', () => {});
        req.end();
      });
    }
    setTimeout(() => aquecerCacheDashboard("startup"), 4500);
    // Pré-aquece o cache com a query mais comum (sem filtros) logo após o startup
    setTimeout(() => {
      const { request } = require('http');
      const PORT_WU = process.env.PORT || 3000;
      const req = request({ hostname: 'localhost', port: PORT_WU, path: '/api/dashboard/agregados' }, res => {
        res.resume();
        console.log('🔥 Cache pré-aquecido');
      });
      req.on('error', () => {});
      req.end();
    }, 4000);

    // Seed usuário inicial de importação a partir das variáveis de ambiente
    if (!READ_ONLY) {
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
        filename: "modelo_categorias_depara.xlsx",
        nome:     "De/Para Categorias"
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
    // Migração: garante que De/Para Categorias existe como um único registro xlsx
    {
      // Remove qualquer entrada csv antiga
      await db.collection("templates_importacao").deleteMany({ filename: "modelo_categorias_depara.csv" });

      // Remove entradas xlsx duplicadas, mantendo apenas a mais recente
      const todosXlsx = await db.collection("templates_importacao")
        .find({ filename: "modelo_categorias_depara.xlsx" })
        .sort({ atualizadoEm: -1 })
        .toArray();
      if (todosXlsx.length > 1) {
        const idsParaDeletar = todosXlsx.slice(1).map(r => r._id);
        await db.collection("templates_importacao").deleteMany({ _id: { $in: idsParaDeletar } });
        console.log(`🧹 ${idsParaDeletar.length} duplicata(s) de modelo_categorias_depara.xlsx removida(s)`);
      }
    }

    // Seed super-admin no MongoDB (permite reset de senha por e-mail)
    const adminExistente = await db.collection("usuarios_admin").findOne({ usuario: process.env.ADMIN_USER });
    if (!adminExistente && process.env.ADMIN_USER && process.env.ADMIN_PASSWORD) {
      await db.collection("usuarios_admin").insertOne({
        usuario:  process.env.ADMIN_USER,
        senha:    hashSenha(process.env.ADMIN_PASSWORD),
        email:    process.env.ADMIN_EMAIL || "",
        usuarioPai: normalizarUsuario(process.env.ADMIN_USER) === USUARIO_PAI_PADRAO,
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
    await garantirUsuarioPai(db);
    await db.collection("usuarios_importacao").createIndex({ usuario: 1 }, { unique: true });

    // Índices de performance para dados_brutos (queries de dashboard)
    await Promise.all([
      db.collection("dados_brutos").createIndex({ "Ano": 1, "Mês": 1, "Loja": 1 }),
      db.collection("dados_brutos").createIndex({ "Ano": 1, "Mês": 1, "Data": 1 }),
      db.collection("dados_brutos").createIndex({ "Ano": 1, "Mês": 1 }),
      db.collection("dados_brutos").createIndex({ "Loja": 1 }),
      db.collection("dados_brutos").createIndex({ "GTIN/PLU": 1 }),
      db.collection("dados_brutos").createIndex({ "_gtin": 1 }),
      db.collection("dados_brutos").createIndex({ "_data_iso": 1 }),
      db.collection("dados_brutos").createIndex({ "Ano": 1, "_data_iso": 1, "Loja": 1 }),
      db.collection("dados_brutos").createIndex({ "_data_iso": -1, "importado_em": -1 }),
      db.collection("categorias_depara").createIndex({ "CODBARRAS": 1 })
    ]);
    console.log("📊 Índices de dashboard criados/verificados");

    // TTL automático para tokens de reset expirados (importação e admin)
    await db.collection("tokens_reset").createIndex({ expira: 1 }, { expireAfterSeconds: 0 });
    }

    app.get("/", (req, res) => {
      res.sendFile(path.join(frontendPath, "index.html"));
    });

    app.get("/api/config", (req, res) => {
      res.json({
        readOnly: READ_ONLY,
        ambiente: READ_ONLY ? "teste" : "producao"
      });
    });

    app.get("/reset-senha", (req, res) => {
      res.sendFile(path.join(frontendPath, "reset-senha.html"));
    });

    // ─────────────────────────────────────
    // TEMPLATES DE IMPORTAÇÃO
    // ─────────────────────────────────────

    // Templates XLSX gerados dinamicamente (De/Para) — CODBARRAS formatado como texto
    const TEMPLATES_XLSX = {
      "modelo_categorias_depara.xlsx": {
        colunas: ["CODBARRAS", "CATEGORIA", "FAMILIA", "NOME PRODUTO"],
        exemplo:  ["7891234567890", "Cosméticos", "Hidratantes", "Creme Hidratante Corporal 200ml"]
      },
      "modelo_lojas_depara.xlsx": {
        colunas: ["Cod_Loja", "Nome_Fantasia"],
        exemplo:  ["001", "Loja Centro"]
      }
    };

    // Download público — sem autenticação
    app.get("/api/templates/:filename", async (req, res) => {
      try {
        const { filename } = req.params;

        // Se há binário customizado salvo pelo usuário, serve ele com prioridade
        if (filename.endsWith(".xlsx")) {
          const stored = await db.collection("templates_importacao").findOne({ filename });
          if (stored?.conteudoBase64) {
            res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
            return res.send(Buffer.from(stored.conteudoBase64, "base64"));
          }
        }

        // Gera XLSX on-the-fly para os De/Para (preserva GTINs como texto)
        if (TEMPLATES_XLSX[filename]) {
          const tpl = TEMPLATES_XLSX[filename];
          const wb  = XLSX.utils.book_new();
          const ws  = XLSX.utils.aoa_to_sheet([tpl.colunas, tpl.exemplo]);

          // Força coluna CODBARRAS como texto para que Excel não converta em notação científica
          const codIdx = tpl.colunas.indexOf("CODBARRAS");
          if (codIdx >= 0) {
            const colLetra = String.fromCharCode(65 + codIdx);
            // Linha de cabeçalho (row 1) e linha de exemplo (row 2)
            [`${colLetra}1`, `${colLetra}2`].forEach(addr => {
              if (ws[addr]) { ws[addr].t = 's'; ws[addr].z = '@'; }
            });
            // Formato de coluna: '@' = texto
            if (!ws['!cols']) ws['!cols'] = tpl.colunas.map(() => ({}));
            ws['!cols'][codIdx] = { wch: 20, numFmt: '@' };
          }

          XLSX.utils.book_append_sheet(wb, ws, "Dados");
          const buffer = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });

          res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
          res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
          return res.send(buffer);
        }

        // CSV para dados_brutos (mantém comportamento atual)
        const template = await db.collection("templates_importacao").findOne({ filename });
        if (!template) return res.status(404).json({ erro: "Template não encontrado." });
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="${template.filename}"`);
        res.send("﻿" + template.conteudo);
      } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar template.", detalhe: error.message });
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
        let update;
        if (filename.endsWith(".xlsx")) {
          const buffer = fs.readFileSync(req.file.path);
          fs.unlinkSync(req.file.path);
          update = { $set: { conteudoBase64: buffer.toString("base64"), atualizadoEm: new Date() }, $unset: { conteudo: "" } };
        } else {
          const conteudo = fs.readFileSync(req.file.path, "utf-8");
          fs.unlinkSync(req.file.path);
          update = { $set: { conteudo, atualizadoEm: new Date() } };
        }

        const result = await db.collection("templates_importacao").updateOne({ filename }, update);

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

    app.put("/api/admin/usuarios/:id/usuario", verificarTokenAdmin, async (req, res) => {
      const usuario = (req.body.usuario || "").trim();
      if (!usuario) return res.status(400).json({ erro: "Nome de usuario e obrigatorio." });

      try {
        const _id = new ObjectId(req.params.id);
        const existente = await db.collection("usuarios_importacao").findOne({
          usuario,
          _id: { $ne: _id }
        });
        if (existente) return res.status(400).json({ erro: "Usuario ja existe." });

        const result = await db.collection("usuarios_importacao").updateOne(
          { _id },
          { $set: { usuario } }
        );
        if (!result.matchedCount) return res.status(404).json({ erro: "Usuario nao encontrado." });

        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao atualizar usuario.", detalhe: error.message });
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
        const admin = await db.collection("usuarios_admin").findOne({ _id: new ObjectId(req.params.id) });
        if (admin?.usuarioPai) {
          return res.status(400).json({ erro: "O usuario pai nao pode ser excluido." });
        }
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
        const admin = await db.collection("usuarios_admin").findOne({ _id: new ObjectId(req.params.id) });
        if (admin?.usuarioPai) {
          return res.status(400).json({ erro: "A senha do usuario pai deve ser alterada apenas por e-mail." });
        }
        await db.collection("usuarios_admin").updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { senha: hashSenha(senha) } }
        );
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao alterar senha.", detalhe: error.message });
      }
    });

    app.put("/api/admin/admins/:id/usuario", verificarTokenAdmin, async (req, res) => {
      const usuario = (req.body.usuario || "").trim();
      if (!usuario) return res.status(400).json({ erro: "Nome de usuario e obrigatorio." });

      try {
        const _id = new ObjectId(req.params.id);
        const existente = await db.collection("usuarios_admin").findOne({
          usuario,
          _id: { $ne: _id }
        });
        if (existente) return res.status(400).json({ erro: "Usuario ja existe." });

        const result = await db.collection("usuarios_admin").updateOne(
          { _id },
          { $set: { usuario } }
        );
        if (!result.matchedCount) return res.status(404).json({ erro: "Admin nao encontrado." });

        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao atualizar admin.", detalhe: error.message });
      }
    });

    app.put("/api/admin/admins/:id/email", verificarTokenAdmin, async (req, res) => {
      const { email } = req.body;
      try {
        const admin = await db.collection("usuarios_admin").findOne({ _id: new ObjectId(req.params.id) });
        if (admin?.usuarioPai) {
          return res.status(400).json({ erro: "O e-mail do usuario pai nao pode ser alterado pelo painel." });
        }
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
    // ─────────────────────────────────────
    // RESUMO DASHBOARD
    // ─────────────────────────────────────
    app.get("/api/dashboard/resumo", async (req, res) => {
      try {
        const pipeline = [
          {
            $group: {
              _id: null,
              total_vendido: { $sum: _migNumericos ? "$_qtd_num"   : brToDouble({ $getField: "Venda (Qtd)" }) },
              total_valor:   { $sum: _migNumericos ? "$_valor_num" : brValorExpr() },
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
    // ─────────────────────────────────────
    // AGREGADOS DASHBOARD (qtd + valor, por loja / cat / fam / dia)
    // ─────────────────────────────────────
    app.get("/api/dashboard/agregados", async (req, res) => {
      try {
        const cacheKey = await dashboardCacheKey('agre:v10', req.query);
        const cached = cacheGet(cacheKey);
        if (cached) return res.json(cached);

        const { ano, mes, loja, cat, familia, produto, produto_gtin } = req.query;
        const di       = req.query.di            || null; // data início YYYY-MM-DD
        const df       = req.query.df            || null; // data fim    YYYY-MM-DD
        const aLoja    = req.query.ativo_loja    || null;
        const aCat     = req.query.ativo_cat     || null;
        const aFamilia = req.query.ativo_familia || null;
        const incluirDiaDetalhado = req.query.detalhe_dia === "1";
        const apenasLoja = req.query.escopo === "loja";

        // Join com categorias_depara em tempo de query.
        // Quando _migGtin=true (todos os docs têm _gtin), usa localField/foreignField
        // que aproveita o índice em categorias_depara.CODBARRAS — O(N×log M).
        // Caso contrário, usa let/pipeline/$expr com $toString em ambos os lados para
        // garantir comparação correta independente do tipo (número vs string).
        const joinCat = _migGtin
          ? [
              { $lookup: { from: "categorias_depara", localField: "_gtin", foreignField: "CODBARRAS", as: "_c" } },
              { $addFields: { _cat: { $ifNull: [{ $arrayElemAt: ["$_c.CATEGORIA", 0] }, "$_cat"] }, _fam: { $ifNull: [{ $arrayElemAt: ["$_c.FAMILIA", 0] }, "$_fam"] }, _prod: produtoDeParaExpr() } }
            ]
          : [
              { $lookup: {
                  from: "categorias_depara",
                  let: { gtin: { $toString: { $ifNull: ["$_gtin", { $getField: "GTIN/PLU" }] } } },
                  pipeline: [{ $match: { $expr: { $eq: ["$$gtin", { $toString: "$CODBARRAS" }] } } }],
                  as: "_c"
              }},
              { $addFields: { _cat: { $ifNull: [{ $arrayElemAt: ["$_c.CATEGORIA", 0] }, "$_cat"] }, _fam: { $ifNull: [{ $arrayElemAt: ["$_c.FAMILIA", 0] }, "$_fam"] }, _prod: produtoDeParaExpr() } }
            ];

        // Usa campos numéricos pré-computados quando disponíveis
        const grp = {
          qty:   { $sum: _migNumericos ? "$_qtd_num"  : brToDouble({ $getField: "Venda (Qtd)" }) },
          valor: { $sum: _migNumericos ? "$_valor_num" : brValorExpr() }
        };

        const AGG_OPTS = { allowDiskUse: true };

        // ── Estágios comuns (rodados uma única vez antes do $facet) ──────────
        const preStages = [];

        // Match base aproveita os índices existentes (Ano, Mês, Loja, _data_iso)
        const baseMatch = {};
        if (ano)  aplicarFiltroAno(baseMatch, ano);
        if (mes)  aplicarFiltroMes(baseMatch, mes);
        if (loja) baseMatch["Loja"] = matchTextoOuNumeroLista(loja);
        if (produto_gtin && _migGtin) baseMatch["_gtin"] = matchListaTexto(produto_gtin);
        if ((di || df) && _migData) {
          const dr = {};
          if (di) dr.$gte = di;
          if (df) dr.$lte = df;
          baseMatch["_data_iso"] = dr;
        }
        if (Object.keys(baseMatch).length) preStages.push({ $match: baseMatch });

        // Fallback de data quando _migData ainda é false
        if ((di || df) && !_migData) {
          const conds = [];
          const isoExpr = { $dateToString: { date: { $ifNull: [
            { $dateFromString: { dateString: { $toString: { $ifNull: [{ $getField: "Data" }, ""] } }, format: "%d/%m/%Y", onError: null, onNull: null } },
            { $dateFromString: { dateString: { $toString: { $ifNull: [{ $getField: "Data" }, ""] } }, format: "%Y-%m-%d", onError: null, onNull: null } }
          ]}, format: "%Y-%m-%d", onNull: "" }};
          if (di) conds.push({ $gte: [isoExpr, di] });
          if (df) conds.push({ $lte: [isoExpr, df] });
          preStages.push({ $match: { $expr: conds.length === 1 ? conds[0] : { $and: conds } } });
        }

        // Join único (uma vez para todos os facets de cat/fam/produto) — pulado quando _cat já está pré-computado
        const precisaCategoria = !apenasLoja || !!(cat || familia || produto || aCat || aFamilia || incluirDiaDetalhado);
        if (precisaCategoria && (!_migCat || (produto && !produto_gtin))) {
          if (_catCountCache < 0) _catCountCache = await db.collection("categorias_depara").estimatedDocumentCount();
          if (_catCountCache > 0) preStages.push(...joinCat);
        }
        if (produto_gtin && !_migGtin) {
          const gtins = listaParam(produto_gtin);
          if (gtins.length) {
            preStages.push({ $match: { $expr: { $in: [{ $toString: { $ifNull: ["$_gtin", { $getField: "GTIN/PLU" }] } }, gtins] } } });
          }
        }
        if (produto && !produto_gtin) {
          preStages.push({ $addFields: { _prod: { $ifNull: ["$_prod", produtoNomeExpr()] } } });
        }

        // Filtros dropdown de cat/fam/produto — comuns a todos os branches do facet
        if (cat)     preStages.push({ $match: { _cat: matchListaTexto(cat) } });
        if (familia) preStages.push({ $match: { _fam: matchListaTexto(familia) } });
        if (produto && !produto_gtin) preStages.push({ $match: { _prod: matchListaTexto(produto) } });

        // Filtros ativos (clique no gráfico) — aplicados seletivamente por branch
        const mLoja    = aLoja    ? [{ $match: { "Loja": matchTextoOuNumero(aLoja) } }]   : [];
        const mCat     = aCat     ? [{ $match: { _cat: aCat } }]              : [];
        const mFamilia = aFamilia ? [{ $match: { _fam: aFamilia } }]          : [];

        const anoRefMensal = await anoReferenciaMensal(ano);
        const dateGroupExpr = {
          $ifNull: [
            _migData ? dataIsoValidaExpr() : null,
            dataValidaPorCampoDataExpr(),
            dataFallbackPorMesExpr(anoRefMensal)
          ]
        };

        // Um único $facet — uma varredura, um join
        const facets = {
          por_loja: [
            ...mCat, ...mFamilia,
            { $group: { _id: "$Loja", ...grp } },
            { $sort: { qty: -1 } }
          ]
        };

        if (!apenasLoja) {
          facets.por_dia = [
            ...mLoja, ...mCat, ...mFamilia,
            { $group: { _id: dateGroupExpr, ...grp } },
            { $sort: { _id: 1 } }
          ];
          facets.por_cat = [
            ...mLoja, ...mFamilia,
            { $group: { _id: "$_cat", ...grp } },
            { $sort: { qty: -1 } }
          ];
          facets.por_fam = [
            ...mLoja, ...mCat,
            { $group: { _id: "$_fam", ...grp } },
            { $sort: { qty: -1 } }
          ];
        }

        if (incluirDiaDetalhado) {
          facets.por_cat_dia = [
            ...mLoja, ...mFamilia,
            { $group: { _id: { cat: "$_cat", data: dateGroupExpr }, ...grp } },
            { $sort: { "_id.data": 1, qty: -1 } }
          ];
          facets.por_fam_dia = [
            ...mLoja, ...mCat,
            { $group: { _id: { fam: "$_fam", data: dateGroupExpr }, ...grp } },
            { $sort: { "_id.data": 1, qty: -1 } }
          ];
        }

        const [facet] = await db.collection("dados_brutos").aggregate([
          ...preStages,
          { $facet: facets }
        ], AGG_OPTS).toArray();

        const result = {
          por_loja: (facet?.por_loja || []).map(r => ({ loja: r._id,                         qty: r.qty, valor: r.valor })),
          por_cat:  (facet?.por_cat  || []).map(r => ({ cat:  r._id || "Sem mapeamento",     qty: r.qty, valor: r.valor })),
          por_fam:  (facet?.por_fam  || []).map(r => ({ fam:  r._id || "Sem mapeamento",     qty: r.qty, valor: r.valor })),
          por_dia:  (facet?.por_dia  || []).map(r => ({ data: r._id,                         qty: r.qty, valor: r.valor })),
          por_cat_dia: (facet?.por_cat_dia || []).map(r => ({ cat: r._id.cat || "Sem mapeamento", data: r._id.data, qty: r.qty, valor: r.valor })),
          por_fam_dia: (facet?.por_fam_dia || []).map(r => ({ fam: r._id.fam || "Sem mapeamento", data: r._id.data, qty: r.qty, valor: r.valor }))
        };
        cacheSet(cacheKey, result);
        res.json(result);
      } catch(e) {
        res.status(500).json({ erro: "Erro ao agregar dados", detalhe: e.message });
      }
    });

    app.get("/api/dashboard/estoque-resumo", async (req, res) => {
      try {
        const cacheKey = await dashboardCacheKey('est-resumo:v6', req.query);
        const cached = cacheGet(cacheKey);
        if (cached) return res.json(cached);

        const { ano, mes, loja, cat, familia, produto, produto_gtin } = req.query;
        const di = req.query.di || null;
        const df = req.query.df || null;

        const baseMatch = {};
        if (ano)  aplicarFiltroAno(baseMatch, ano);
        if (mes)  aplicarFiltroMes(baseMatch, mes);
        if (loja) baseMatch["Loja"] = matchTextoOuNumeroLista(loja);
        if (cat) baseMatch["_cat"] = matchListaTexto(cat);
        if (familia) baseMatch["_fam"] = matchListaTexto(familia);
        if (produto_gtin && _migGtin) baseMatch["_gtin"] = matchListaTexto(produto_gtin);
        if ((di || df) && _migData) {
          const dr = {};
          if (di) dr.$gte = di;
          if (df) dr.$lte = df;
          baseMatch["_data_iso"] = dr;
        }

        const estoqueExpr = { $ifNull: ["$_estoque_num", brToDouble({ $getField: "Estoque Diario" })] };
        const preStages = Object.keys(baseMatch).length ? [{ $match: baseMatch }] : [];
        if (produto_gtin && !_migGtin) {
          const gtins = listaParam(produto_gtin);
          if (gtins.length) {
            preStages.push({ $match: { $expr: { $in: [{ $toString: { $ifNull: ["$_gtin", { $getField: "GTIN/PLU" }] } }, gtins] } } });
          }
        }
        if (produto && !produto_gtin) {
          preStages.push(
            { $addFields: { _gtin_prod_lookup: { $toString: { $ifNull: ["$_gtin", { $getField: "GTIN/PLU" }] } } } },
            { $lookup: { from: "categorias_depara", localField: "_gtin_prod_lookup", foreignField: "CODBARRAS", as: "_c" } },
            { $addFields: { _prod: produtoDeParaExpr() } },
            { $unset: ["_c", "_gtin_prod_lookup"] },
            { $match: { _prod: matchListaTexto(produto) } }
          );
        }
        const latestMatch = { ...baseMatch };
        if (cat && _migCat) latestMatch["_cat"] = matchListaTexto(cat);
        if (familia && _migCat) latestMatch["_fam"] = matchListaTexto(familia);
        const latestDoc = _migData && !(produto && !produto_gtin)
          ? await db.collection("dados_brutos")
              .find(latestMatch, { projection: { _data_iso: 1 } })
              .sort({ _data_iso: -1 })
              .limit(1)
              .next()
          : null;
        let ultimaDataEstoque = latestDoc?._data_iso || null;
        if (!ultimaDataEstoque) {
          const [ultimaDataDoc] = await db.collection("dados_brutos").aggregate([
            ...preStages,
            { $group: { _id: null, data: { $max: dateGroupExpr } } }
          ], { allowDiskUse: true }).toArray();
          ultimaDataEstoque = ultimaDataDoc?.data || null;
        }
        const matchUltimaDataEstoque = ultimaDataEstoque
          ? (_migData
              ? [{ $match: { _data_iso: ultimaDataEstoque } }]
              : [{ $match: { $expr: { $eq: [dateGroupExpr, ultimaDataEstoque] } } }])
          : [];
        const snapshotUltimoDia = req.query.snapshot === "1";
        const facetPreStages = snapshotUltimoDia ? [...preStages, ...matchUltimaDataEstoque] : preStages;

        const [facet] = await db.collection("dados_brutos").aggregate([
          ...facetPreStages,
          { $facet: {
            total: [
              { $group: { _id: null, total: { $sum: estoqueExpr }, lojas: { $addToSet: "$Loja" } } },
              { $project: { _id: 0, total: 1, total_lojas: { $size: "$lojas" } } }
            ],
            por_loja: [
              { $group: { _id: "$Loja", qty: { $sum: estoqueExpr } } },
              { $sort: { qty: -1 } }
            ]
          }}
        ], { allowDiskUse: true }).toArray();

        const result = {
          total: facet?.total?.[0]?.total || 0,
          total_lojas: facet?.total?.[0]?.total_lojas || 0,
          por_loja: (facet?.por_loja || []).map(r => ({ loja: r._id, qty: r.qty }))
        };
        cacheSet(cacheKey, result);
        res.json(result);
      } catch(e) {
        res.status(500).json({ erro: "Erro ao agregar resumo de estoque", detalhe: e.message });
      }
    });

    // ─────────────────────────────────────
    // ESTOQUE AGREGADO (consulta o banco completo, sem limite de rawData)
    // ─────────────────────────────────────
    app.get("/api/dashboard/estoque", async (req, res) => {
      try {
        const cacheKey = req.query.snapshot === "1"
          ? `est:v15:snapshot:${JSON.stringify(req.query)}`
          : await dashboardCacheKey('est:v19', req.query);
        const cached = cacheGet(cacheKey);
        if (cached) return res.json(cached);

        const { ano, mes, loja, cat, familia, produto, produto_gtin } = req.query;
        const di = req.query.di || null;
        const df = req.query.df || null;

        const baseMatch = {};
        if (ano)  aplicarFiltroAno(baseMatch, ano);
        if (mes)  aplicarFiltroMes(baseMatch, mes);
        if (loja) baseMatch["Loja"] = matchTextoOuNumeroLista(loja);
        if (produto_gtin && _migGtin) baseMatch["_gtin"] = matchListaTexto(produto_gtin);
        if ((di || df) && _migData) {
          const dr = {};
          if (di) dr.$gte = di;
          if (df) dr.$lte = df;
          baseMatch["_data_iso"] = dr;
        }
        const preStages = Object.keys(baseMatch).length ? [{ $match: baseMatch }] : [];
        if (!_migCat) {
          preStages.push(
            { $addFields: { _gtin_atual_lookup: { $toString: { $ifNull: ["$_gtin", { $getField: "GTIN/PLU" }] } } } },
            {
              $lookup: {
                from: "categorias_depara",
                localField: "_gtin_atual_lookup",
                foreignField: "CODBARRAS",
                as: "_cat_atual_join"
              }
            },
            {
              $addFields: {
                _cat_atual: { $ifNull: [{ $arrayElemAt: ["$_cat_atual_join.CATEGORIA", 0] }, "$_cat"] },
                _fam_atual: { $ifNull: [{ $arrayElemAt: ["$_cat_atual_join.FAMILIA", 0] }, "$_fam"] }
              }
            },
            { $unset: ["_cat_atual_join", "_gtin_atual_lookup"] }
          );
        }
        const catCampo = _migCat ? "_cat" : "_cat_atual";
        const famCampo = _migCat ? "_fam" : "_fam_atual";
        if (cat)     preStages.push({ $match: { [catCampo]: matchListaTexto(cat) } });
        if (familia) preStages.push({ $match: { [famCampo]: matchListaTexto(familia) } });
        if (produto_gtin && !_migGtin) {
          const gtins = listaParam(produto_gtin);
          if (gtins.length) {
            preStages.push({ $match: { $expr: { $in: [{ $toString: { $ifNull: ["$_gtin", { $getField: "GTIN/PLU" }] } }, gtins] } } });
          }
        }
        if (produto && !produto_gtin) {
          preStages.push(
            { $addFields: { _gtin_prod_lookup: { $toString: { $ifNull: ["$_gtin", { $getField: "GTIN/PLU" }] } } } },
            { $lookup: { from: "categorias_depara", localField: "_gtin_prod_lookup", foreignField: "CODBARRAS", as: "_c" } },
            { $addFields: { _prod: produtoDeParaExpr() } },
            { $unset: ["_c", "_gtin_prod_lookup"] },
            { $match: { _prod: matchListaTexto(produto) } }
          );
        }
        const estoqueExpr = { $ifNull: ["$_estoque_num", brToDouble({ $getField: "Estoque Diario" })] };
        const anoRefMensal = await anoReferenciaMensal(ano);
        const dateGroupExpr = {
          $ifNull: [
            _migData ? dataIsoValidaExpr() : null,
            dataValidaPorCampoDataExpr(),
            dataFallbackPorMesExpr(anoRefMensal)
          ]
        };

        if (req.query.historico === "1") {
          const historico = await db.collection("dados_brutos").aggregate([
            ...preStages,
            { $group: { _id: { loja: "$Loja", data: dateGroupExpr }, qty: { $sum: estoqueExpr } } },
            { $sort: { "_id.data": 1, qty: -1 } }
          ], { allowDiskUse: true }).toArray();

          const lojasNomeMap = await mapaNomesLojas();
          const resultHistorico = {
            por_loja_dia: historico.map(r => ({ loja: r._id.loja, nome: nomeLojaPorCodigo(r._id.loja, lojasNomeMap), data: r._id.data, qty: r.qty }))
          };
          cacheSet(cacheKey, resultHistorico);
          return res.json(resultHistorico);
        }

        const latestMatch = { ...baseMatch };
        if (cat && _migCat) latestMatch["_cat"] = matchListaTexto(cat);
        if (familia && _migCat) latestMatch["_fam"] = matchListaTexto(familia);
        const latestDoc = _migData && !(produto && !produto_gtin)
          ? await db.collection("dados_brutos")
              .find(latestMatch, { projection: { _data_iso: 1 } })
              .sort({ _data_iso: -1 })
              .limit(1)
              .next()
          : null;
        let ultimaDataEstoque = latestDoc?._data_iso || null;
        if (!ultimaDataEstoque) {
          const [ultimaDataDoc] = await db.collection("dados_brutos").aggregate([
            ...preStages,
            { $group: { _id: null, data: { $max: dateGroupExpr } } }
          ], { allowDiskUse: true }).toArray();
          ultimaDataEstoque = ultimaDataDoc?.data || null;
        }
        const matchUltimaDataEstoque = ultimaDataEstoque
          ? (_migData
              ? [{ $match: { _data_iso: ultimaDataEstoque } }]
              : [{ $match: { $expr: { $eq: [dateGroupExpr, ultimaDataEstoque] } } }])
          : [];
        const snapshotUltimoDia = req.query.snapshot === "1";
        const facetPreStages = snapshotUltimoDia ? [...preStages, ...matchUltimaDataEstoque] : preStages;

        const [facet] = await db.collection("dados_brutos").aggregate([
          ...facetPreStages,
          { $facet: {
            total: [
              { $group: { _id: null, total: { $sum: estoqueExpr }, lojas: { $addToSet: "$Loja" } } },
              { $project: { _id: 0, total: 1, total_lojas: { $size: "$lojas" } } }
            ],
            por_loja: [
              { $group: { _id: "$Loja", qty: { $sum: estoqueExpr } } },
              { $sort: { qty: -1 } }
            ],
            por_loja_dia: [
              { $group: { _id: { loja: "$Loja", data: dateGroupExpr }, qty: { $sum: estoqueExpr } } },
              { $sort: { "_id.data": 1, qty: -1 } }
            ],
            por_produto: [
              { $match: { _id: "__skip_acumulado__" } },
              { $group: { _id: { $ifNull: [
                { $getField: "Produto" },
                { $ifNull: [{ $getField: "produto" }, { $getField: "Descrição" }] }
              ]}, qty: { $sum: estoqueExpr } } },
              { $sort: { qty: -1 } }
            ],
            por_produto_dia: [
              ...matchUltimaDataEstoque,
              { $group: { _id: { nome: { $ifNull: [
                { $getField: "Produto" },
                { $ifNull: [{ $getField: "produto" }, { $getField: "DescriÃ§Ã£o" }] }
              ]}, data: dateGroupExpr }, qty: { $sum: estoqueExpr } } },
              { $sort: { "_id.data": 1, qty: -1 } }
            ],
            por_cat: [
              { $match: { _id: "__skip_acumulado__" } },
              { $group: { _id: `$${catCampo}`, qty: { $sum: estoqueExpr } } },
              { $sort: { qty: -1 } }
            ],
            por_cat_dia: [
              ...matchUltimaDataEstoque,
              { $group: { _id: { cat: `$${catCampo}`, data: dateGroupExpr }, qty: { $sum: estoqueExpr } } },
              { $sort: { "_id.data": 1, qty: -1 } }
            ],
            por_fam: [
              { $match: { _id: "__skip_acumulado__" } },
              { $group: { _id: `$${famCampo}`, qty: { $sum: estoqueExpr } } },
              { $sort: { qty: -1 } }
            ],
            por_fam_dia: [
              ...matchUltimaDataEstoque,
              { $group: { _id: { fam: `$${famCampo}`, data: dateGroupExpr }, qty: { $sum: estoqueExpr } } },
              { $sort: { "_id.data": 1, qty: -1 } }
            ]
          }}
        ], { allowDiskUse: true }).toArray();

        const lojasNomeMap = await mapaNomesLojas();
        const result = {
          total:       facet?.total?.[0]?.total       || 0,
          total_lojas: facet?.total?.[0]?.total_lojas || 0,
          por_loja:    (facet?.por_loja || []).map(r => ({ loja: r._id, nome: nomeLojaPorCodigo(r._id, lojasNomeMap), qty: r.qty })),
          por_loja_dia: (facet?.por_loja_dia || []).map(r => ({ loja: r._id.loja, nome: nomeLojaPorCodigo(r._id.loja, lojasNomeMap), data: r._id.data, qty: r.qty })),
          por_produto: (facet?.por_produto || []).map(r => ({ nome: limparTextoExibicao(r._id) || "SEM PRODUTO", qty: r.qty })),
          por_produto_dia: (facet?.por_produto_dia || []).map(r => ({ nome: limparTextoExibicao(r._id.nome) || "SEM PRODUTO", data: r._id.data, qty: r.qty })),
          por_cat: (facet?.por_cat || []).map(r => ({ cat: r._id || "SEM CATEGORIA", qty: r.qty })),
          por_cat_dia: (facet?.por_cat_dia || []).map(r => ({ cat: r._id.cat || "SEM CATEGORIA", data: r._id.data, qty: r.qty })),
          por_fam: (facet?.por_fam || []).map(r => ({ fam: r._id || "SEM FAMÍLIA", qty: r.qty })),
          por_fam_dia: (facet?.por_fam_dia || []).map(r => ({ fam: r._id.fam || "SEM FAMÍLIA", data: r._id.data, qty: r.qty }))
        };

        cacheSet(cacheKey, result);
        res.json(result);
      } catch(e) {
        res.status(500).json({ erro: "Erro ao agregar estoque", detalhe: e.message });
      }
    });

    // ─────────────────────────────────────
    // VENDAS POR FILIAL
    // ─────────────────────────────────────
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
    app.get("/api/dashboard/filtros", async (req, res) => {
      try {
        const [anosRaw, mesesNomeRaw, mesesNumeroRaw, lojasRaw] = await Promise.all([
          db.collection("dados_brutos").distinct("Ano"),
          db.collection("dados_brutos").distinct("MÃªs"),
          db.collection("dados_brutos").distinct("Mes"),
          db.collection("dados_brutos").distinct("Loja")
        ]);

        const anos = [...new Set(anosRaw.map(v => String(v ?? "").trim()).filter(Boolean))]
          .sort();
        const meses = [...new Set([...mesesNomeRaw, ...mesesNumeroRaw]
          .map(normalizarMes)
          .filter(Boolean))]
          .sort((a, b) => MESES_ABREV.indexOf(a) - MESES_ABREV.indexOf(b));
        const lojas = [...new Set(lojasRaw.map(v => String(v ?? "").trim()).filter(Boolean))]
          .sort((a, b) => Number(a) - Number(b));

        res.json({ anos, meses, lojas });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar filtros", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // IMPORTAÇÕES (PROTEGIDAS) — suporte a upload chunked
    // ─────────────────────────────────────

    // Helper: processa um arquivo CSV temporário e insere na coleção
    function dataISODePlanilha(valor) {
      if (valor instanceof Date && !Number.isNaN(valor.getTime())) {
        return valor.toISOString().slice(0, 10);
      }
      if (typeof valor === "number" && Number.isFinite(valor)) {
        const partes = XLSX.SSF.parse_date_code(valor);
        if (partes?.y && partes?.m && partes?.d) {
          return `${partes.y}-${String(partes.m).padStart(2, "0")}-${String(partes.d).padStart(2, "0")}`;
        }
      }
      const dataStr = String(valor || "").trim();
      const brMatch = dataStr.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
      const isoMatch = dataStr.match(/^(\d{4})-(\d{2})-(\d{2})$/);
      if (brMatch) return `${brMatch[3]}-${brMatch[2].padStart(2, "0")}-${brMatch[1].padStart(2, "0")}`;
      if (isoMatch) return dataStr;
      return null;
    }

    async function inserirEmLotes(colecao, resultados, tamanhoLote = 1500) {
      let inserido = 0;
      for (let i = 0; i < resultados.length; i += tamanhoLote) {
        const lote = resultados.slice(i, i + tamanhoLote);
        if (!lote.length) continue;
        await colecao.insertMany(lote, { ordered: false });
        inserido += lote.length;
      }
      return inserido;
    }

    function prepararRegistroDadosBrutos(registro, categoriasPorGtin = null) {
      const qtdRaw = registro['Venda (Qtd)'] ?? registro['Venda Nf Quantidade'] ?? registro['Venda Pdv Quantidade'] ?? 0;
      const valRaw = registro['Venda (R$)'] ?? 0;
      const estRaw = registro['Estoque Diario'] ?? registro['Estoque DiÃ¡rio'] ?? registro['Estoque'] ?? 0;
      const qtd = parseBRNumber(qtdRaw);
      const val = parseBRNumber(valRaw);
      const est = parseBRNumber(estRaw);
      registro._qtd_num = typeof qtd === 'number' ? qtd : (parseFloat(String(qtd)) || 0);
      registro._valor_num = typeof val === 'number' ? val : (parseFloat(String(val)) || 0);
      registro._estoque_num = typeof est === 'number' ? est : (parseFloat(String(est)) || 0);
      registro._gtin = String(registro['GTIN/PLU'] || '').trim() || null;
      const categoria = categoriasPorGtin?.get(registro._gtin);
      registro._cat = categoria?.CATEGORIA || null;
      registro._fam = categoria?.FAMILIA || null;

      const dataIso = dataISODePlanilha(registro['Data']);
      const mesIso = dataIso ? MESES_ABREV[Number(dataIso.slice(5, 7)) - 1] : "";
      const mesCanonico = mesIso || normalizarMes(registro['M\u00EAs'] ?? registro['Mes']);
      if (mesCanonico) {
        registro['M\u00EAs'] = mesCanonico;
        const mesNumero = MESES_ABREV.indexOf(mesCanonico) + 1;
        if (mesNumero > 0 && (registro['Mes'] === undefined || registro['Mes'] === null || registro['Mes'] === "")) {
          registro['Mes'] = mesNumero;
        }
      }

      registro._data_iso = dataIso;
      return registro;
    }

    async function processarChunkCSV(req, colecao, limparColunas, opcoes = {}) {
      let categoriasPorGtin = null;
      if (colecao.collectionName === 'dados_brutos') {
        const categorias = await db.collection("categorias_depara")
          .find({}, { projection: { CODBARRAS: 1, CATEGORIA: 1, FAMILIA: 1 } })
          .toArray();
        categoriasPorGtin = new Map(categorias.map(c => [String(c.CODBARRAS || '').trim(), c]));
      }

      return new Promise((resolve, reject) => {
        const resultados = [];
        const stream = fs.createReadStream(req.file.path).pipe(csv({ separator: ";" }));

        stream.on("data", (linha) => {
          const registro = {};
          Object.keys(linha).forEach((coluna) => {
            const k    = limparColunas ? coluna.trim() : limparValor(coluna);
            const rawV = limparColunas ? linha[coluna].trim() : limparValor(linha[coluna]);
            let v = parseBRNumber(rawV);
            // Normaliza campos de código de barras (trata notação científica do Excel)
            if (/^(codbarras|gtin|ean|plu)/i.test(k.trim()) || k.trim() === 'GTIN/PLU') v = normalizarEAN(v);
            registro[k] = v;
          });
          if (opcoes.extraCampos) Object.assign(registro, opcoes.extraCampos);

          // Pré-computa campos numéricos, _gtin e _data_iso para queries indexadas
          if (colecao.collectionName === 'dados_brutos') {
            const qtdRaw = registro['Venda (Qtd)'] ?? registro['Venda Nf Quantidade'] ?? registro['Venda Pdv Quantidade'] ?? 0;
            const valRaw = registro['Venda (R$)'] ?? 0;
            const estRaw = registro['Estoque Diario'] ?? registro['Estoque Diário'] ?? registro['Estoque'] ?? 0;
            const qtd = parseBRNumber(qtdRaw);
            const val = parseBRNumber(valRaw);
            const est = parseBRNumber(estRaw);
            registro._qtd_num   = typeof qtd === 'number' ? qtd : (parseFloat(String(qtd)) || 0);
            registro._valor_num = typeof val === 'number' ? val : (parseFloat(String(val)) || 0);
            registro._estoque_num = typeof est === 'number' ? est : (parseFloat(String(est)) || 0);
            registro._gtin      = String(registro['GTIN/PLU'] || '').trim() || null;
            const categoria = categoriasPorGtin?.get(registro._gtin);
            registro._cat = categoria?.CATEGORIA || null;
            registro._fam = categoria?.FAMILIA || null;
            // Converte Data (DD/MM/AAAA ou AAAA-MM-DD) para string ISO AAAA-MM-DD
            const dataStr = String(registro['Data'] || '').trim();
            const mesCanonico = mesDeData(dataStr) || normalizarMes(registro['Mês'] ?? registro['Mes']);
            if (mesCanonico) {
              registro['M\u00EAs'] = mesCanonico;
              const mesNumero = MESES_ABREV.indexOf(mesCanonico) + 1;
              if (mesNumero > 0 && (registro['Mes'] === undefined || registro['Mes'] === null || registro['Mes'] === "")) {
                registro['Mes'] = mesNumero;
              }
            }
            const brMatch  = dataStr.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
            const isoMatch = dataStr.match(/^(\d{4})-(\d{2})-(\d{2})$/);
            if (brMatch) {
              registro._data_iso = `${brMatch[3]}-${brMatch[2].padStart(2,'0')}-${brMatch[1].padStart(2,'0')}`;
            } else if (isoMatch) {
              registro._data_iso = dataStr;
            } else {
              registro._data_iso = null;
            }
          }

          resultados.push(registro);
        });

        stream.on("error", reject);

        stream.on("end", async () => {
          try {
            if (opcoes.deleteFirst) await colecao.deleteMany({});
            const inserido = await inserirEmLotes(colecao, resultados);
            try { fs.unlinkSync(req.file.path); } catch (_) {}
            resolve(inserido);
          } catch (err) {
            try { fs.unlinkSync(req.file.path); } catch (_) {}
            reject(err);
          }
        });
      });
    }

    // Helper: processa XLSX (De/Para categorias e lojas) — preserva GTINs com precisão total
    async function processarXLSX(req, colecao, opcoes = {}) {
      let categoriasPorGtin = null;
      if (colecao.collectionName === 'dados_brutos') {
        const categorias = await db.collection("categorias_depara")
          .find({}, { projection: { CODBARRAS: 1, CATEGORIA: 1, FAMILIA: 1 } })
          .toArray();
        categoriasPorGtin = new Map(categorias.map(c => [String(c.CODBARRAS || '').trim(), c]));
      }

      const workbook = XLSX.readFile(req.file.path, { type: 'file', raw: true });
      try { fs.unlinkSync(req.file.path); } catch (_) {}

      const sheetName = workbook.SheetNames[0];
      const rows = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { raw: true, defval: '' });

      const resultados = rows.map(linha => {
        const registro = {};
        Object.keys(linha).forEach(coluna => {
          const k    = coluna.trim();
          const rawV = linha[coluna];
          // Normaliza campos de código de barras — números inteiros do Excel têm precisão total
          if (/^(codbarras|gtin|ean|plu)/i.test(k) || k === 'GTIN/PLU') {
            registro[k] = normalizarEAN(rawV);
          } else {
            const valor = colecao.collectionName === 'dados_brutos' ? parseBRNumber(rawV) : rawV;
            registro[k] = valor === '' ? null : valor;
          }
        });
        if (opcoes.extraCampos) Object.assign(registro, opcoes.extraCampos);
        if (colecao.collectionName === 'dados_brutos') prepararRegistroDadosBrutos(registro, categoriasPorGtin);
        return registro;
      });

      if (opcoes.deleteFirst) await colecao.deleteMany({});
      return inserirEmLotes(colecao, resultados);
    }

    async function aplicarRetencaoDadosBrutos(mesesParaManter = 13) {
      const meses = await db.collection("dados_brutos").aggregate([
        { $match: { _data_iso: { $type: "string", $regex: /^\d{4}-\d{2}-\d{2}$/ } } },
        { $project: { mes: { $substr: ["$_data_iso", 0, 7] } } },
        { $group: { _id: "$mes" } },
        { $sort: { _id: -1 } }
      ]).toArray();

      if (meses.length <= mesesParaManter) {
        return {
          aplicado: false,
          mesesEncontrados: meses.length,
          mesesMantidos: meses.map(m => m._id),
          mesesRemovidos: [],
          registrosRemovidos: 0,
          logsRemovidos: 0
        };
      }

      const mesesMantidos = meses.slice(0, mesesParaManter).map(m => m._id);
      const mesesRemovidos = meses.slice(mesesParaManter).map(m => m._id);
      const limiteData = `${mesesMantidos[mesesMantidos.length - 1]}-01`;

      const result = await db.collection("dados_brutos").deleteMany({ _data_iso: { $lt: limiteData } });
      const importIdsAtivos = await db.collection("dados_brutos").distinct("_import_id", {
        _import_id: { $exists: true, $ne: null }
      });
      const logsResult = await db.collection("logs_importacao").deleteMany({
        tipo: "dados_brutos",
        importId: { $nin: importIdsAtivos }
      });

      await atualizarFlagsMigracao();

      return {
        aplicado: true,
        mesesEncontrados: meses.length,
        mesesMantidos,
        mesesRemovidos,
        registrosRemovidos: result.deletedCount,
        logsRemovidos: logsResult.deletedCount,
        limiteMes: mesesMantidos[mesesMantidos.length - 1]
      };
    }

    app.post("/api/importar/dados-brutos", verificarToken, upload.single("file"), async (req, res) => {
      if (!req.file) return res.status(400).json({ erro: "Nenhum arquivo enviado." });

      const importId     = req.body.importId    || crypto.randomBytes(8).toString("hex");
      const chunkIndex   = parseInt(req.body.chunkIndex   ?? "0",  10);
      const totalChunks  = parseInt(req.body.totalChunks  ?? "1",  10);
      const totalRecords = parseInt(req.body.totalRecords ?? "0",  10);
      const nomeArquivo  = req.file.originalname || req.file.filename;
      const substituir   = req.body.substituir === 'true';
      const extArquivo   = path.extname(nomeArquivo).toLowerCase();

      try {
        let retencao = null;
        // Modo substituir: apaga todos os dados brutos existentes antes do primeiro lote
        if (substituir && chunkIndex === 0) {
          await db.collection("dados_brutos").deleteMany({});
          await db.collection("logs_importacao").deleteMany({ tipo: "dados_brutos" });
          cacheClear();
          _migNumericos = false; _migGtin = false; _migData = false; _migCat = false; _catCountCache = -1;
        }

        const opcoesImportacao = { extraCampos: { importado_em: new Date(), _import_id: importId } };
        const inserido = extArquivo === '.xls' || extArquivo === '.xlsx'
          ? await processarXLSX(req, db.collection("dados_brutos"), opcoesImportacao)
          : await processarChunkCSV(req, db.collection("dados_brutos"), false, opcoesImportacao);

        const isUltimo = extArquivo === '.xls' || extArquivo === '.xlsx' || chunkIndex === totalChunks - 1;
        if (isUltimo) {
          await db.collection("logs_importacao").insertOne({
            importId, tipo: "dados_brutos", arquivo: nomeArquivo,
            usuario: req.usuarioLogado, total: totalRecords || inserido, data: new Date()
          });
          retencao = await aplicarRetencaoDadosBrutos(13);
          cacheClear();
          await atualizarFlagsMigracao();
        }

        res.json({
          ok: true,
          inserido,
          ultimo: isUltimo,
          retencao,
          mensagem: isUltimo ? "Importação finalizada 🚀" : "Lote salvo"
        });
      } catch (error) {
        try { if (req.file?.path) fs.unlinkSync(req.file.path); } catch (_) {}
        if (importId) {
          await db.collection("dados_brutos").deleteMany({ _import_id: importId });
          await db.collection("logs_importacao").deleteMany({ importId, tipo: "dados_brutos" });
          cacheClear();
        }
        res.status(500).json({ erro: "Erro ao salvar no banco de dados", detalhe: error.message });
      }
    });

    app.post("/api/importar/dados-brutos/cancelar", verificarToken, async (req, res) => {
      try {
        const { importId } = req.body || {};
        if (!importId) return res.status(400).json({ erro: "importId obrigatorio." });

        const result = await db.collection("dados_brutos").deleteMany({ _import_id: importId });
        await db.collection("logs_importacao").deleteMany({ importId, tipo: "dados_brutos" });
        cacheClear();
        await atualizarFlagsMigracao();

        res.json({ ok: true, removidos: result.deletedCount });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao cancelar importacao.", detalhe: error.message });
      }
    });

    app.post("/api/importar/categorias-depara", verificarToken, upload.single("file"), async (req, res) => {
      if (!req.file) return res.status(400).json({ erro: "Nenhum arquivo enviado." });
      const importId    = req.body.importId || crypto.randomBytes(8).toString("hex");
      const nomeArquivo = req.file.originalname || req.file.filename;
      try {
        const inserido = await processarXLSX(req, db.collection("categorias_depara"), {
          deleteFirst: true,
          extraCampos: { _import_id: importId }
        });
        await db.collection("logs_importacao").insertOne({
          importId, tipo: "categorias_depara", arquivo: nomeArquivo,
          usuario: req.usuarioLogado, total: inserido, data: new Date()
        });
        cacheClear();
        // Re-migra _cat/_fam com o novo de/para (em background, sem bloquear a resposta)
        _migCat = false; _catCountCache = -1;
        migrarCamposBackground();
        res.json({ ok: true, inserido, ultimo: true, mensagem: "Categorias importadas" });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao salvar no banco de dados", detalhe: error.message });
      }
    });

    app.post("/api/importar/lojas-depara", verificarToken, upload.single("file"), async (req, res) => {
      if (!req.file) return res.status(400).json({ erro: "Nenhum arquivo enviado." });
      const importId    = req.body.importId || crypto.randomBytes(8).toString("hex");
      const nomeArquivo = req.file.originalname || req.file.filename;
      try {
        const inserido = await processarXLSX(req, db.collection("lojas_depara"), {
          deleteFirst: true,
          extraCampos: { _import_id: importId }
        });
        await db.collection("logs_importacao").insertOne({
          importId, tipo: "lojas_depara", arquivo: nomeArquivo,
          usuario: req.usuarioLogado, total: inserido, data: new Date()
        });
        cacheClear();
        res.json({ ok: true, inserido, ultimo: true, mensagem: "Lojas importadas" });
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

    app.delete("/api/admin/logs-importacao", verificarTokenAdmin, async (req, res) => {
      try {
        const { senha } = req.body || {};
        if (!senha) return res.status(401).json({ erro: "Senha obrigatória." });
        const adminAutorizado = await obterUsuarioPai(db);
        if (!adminAutorizado || !verificarSenha(senha, adminAutorizado.senha)) {
          return res.status(401).json({ erro: "Apenas a senha do usuario pai libera esta limpeza." });
        }
        await db.collection("logs_importacao").deleteMany({});
        res.json({ ok: true });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao limpar histórico.", detalhe: error.message });
      }
    });

    // Apaga TODOS os dados brutos e os logs associados (operação irreversível, requer senha de admin)
    app.delete("/api/admin/dados-brutos", verificarTokenAdmin, async (req, res) => {
      try {
        const { senha } = req.body || {};
        if (!senha) return res.status(401).json({ erro: "Senha obrigatória." });
        const adminAutorizado = await obterUsuarioPai(db);
        if (!adminAutorizado || !verificarSenha(senha, adminAutorizado.senha)) {
          return res.status(401).json({ erro: "Apenas a senha do usuario pai libera esta limpeza." });
        }
        const result = await db.collection("dados_brutos").deleteMany({});
        await db.collection("logs_importacao").deleteMany({ tipo: "dados_brutos" });
        cacheClear();
        _migNumericos = false; _migGtin = false; _migData = false; _migCat = false; _catCountCache = -1;
        res.json({ ok: true, deletados: result.deletedCount });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao limpar dados brutos.", detalhe: error.message });
      }
    });

    app.delete("/api/admin/logs-importacao/:id", verificarTokenAdmin, async (req, res) => {
      try {
        const log = await db.collection("logs_importacao").findOne({ _id: new ObjectId(req.params.id) });
        if (!log) return res.status(404).json({ erro: "Log não encontrado." });

        let removidos = 0;
        if (log.tipo === "dados_brutos") {
          const result = await db.collection("dados_brutos").deleteMany({ _import_id: log.importId });
          removidos = result.deletedCount;
          await atualizarFlagsMigracao();
        } else if (log.tipo === "categorias_depara") {
          const result = await db.collection("categorias_depara").deleteMany({});
          removidos = result.deletedCount;
          _migCat = false;
          _catCountCache = -1;
        } else if (log.tipo === "lojas_depara") {
          const result = await db.collection("lojas_depara").deleteMany({});
          removidos = result.deletedCount;
        }

        await db.collection("logs_importacao").deleteOne({ _id: new ObjectId(req.params.id) });
        cacheClear();
        res.json({ ok: true, removidos });
      } catch (error) {
        res.status(500).json({ erro: "Erro ao desfazer importação.", detalhe: error.message });
      }
    });

    // ─────────────────────────────────────
    // MIGRAÇÃO DE PERFORMANCE (dados existentes)
    // ─────────────────────────────────────
    app.post("/api/admin/migrar-campos", verificarTokenAdmin, async (req, res) => {
      try {
        let totalNum = 0, totalGtin = 0, totalData = 0, totalMes = 0;

        // 1. Pré-computa _qtd_num e _valor_num via pipeline MongoDB (server-side, sem transferência)
        const numResult = await db.collection("dados_brutos").updateMany(
          { _qtd_num: { $exists: false } },
          [{ $set: {
            _qtd_num:   brToDouble({ $getField: "Venda (Qtd)" }),
            _valor_num: brValorExpr()
          }}]
        );
        totalNum = numResult.modifiedCount;

        // 2. Pré-computa _gtin a partir de GTIN/PLU (habilita join indexado em tempo de query)
        const gtinResult = await db.collection("dados_brutos").updateMany(
          { _gtin: { $exists: false } },
          [{ $set: { _gtin: { $toString: { $ifNull: [{ $getField: "GTIN/PLU" }, ""] } } } }]
        );
        totalGtin = gtinResult.modifiedCount;

        // 3. Pré-computa _data_iso (YYYY-MM-DD) a partir de Data (DD/MM/YYYY ou YYYY-MM-DD)
        // Reprocessa também registros onde _data_iso=null mas Data existe
        const dataResult = await db.collection("dados_brutos").updateMany(
          { $and: [{ $or: [{ _data_iso: { $exists: false } }, { _data_iso: null }] }, { Data: { $exists: true, $ne: "" } }] },
          [{ $set: {
            _data_iso: {
              $let: {
                vars: { d: { $toString: { $ifNull: [{ $getField: "Data" }, ""] } } },
                in: {
                  $dateToString: {
                    date: { $ifNull: [
                      { $dateFromString: { dateString: "$$d", format: "%d/%m/%Y", onError: null, onNull: null } },
                      { $dateFromString: { dateString: "$$d", format: "%Y-%m-%d", onError: null, onNull: null } }
                    ]},
                    format: "%Y-%m-%d",
                    onNull: null
                  }
                }
              }
            }
          }}]
        );
        totalData = dataResult.modifiedCount;

        const mesResult = await db.collection("dados_brutos").updateMany(
          filtroMesDivergente(),
          [{ $set: { "Mês": mesAbrevPorIsoExpr() } }]
        );
        totalMes = mesResult.modifiedCount;

        _migNumericos = true;
        _migGtin      = true;
        _migData      = true;
        cacheClear();

        console.log(`✅ Migração concluída: ${totalNum} numéricos, ${totalGtin} gtin, ${totalData} data_iso, ${totalMes} meses`);
        res.json({ ok: true, numericosAtualizados: totalNum, gtinAtualizados: totalGtin, dataIsoAtualizados: totalData, mesesAtualizados: totalMes });
      } catch(e) {
        console.error("❌ Erro na migração:", e.message);
        res.status(500).json({ erro: "Erro na migração", detalhe: e.message });
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
