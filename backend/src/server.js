const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
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
// AUTH — SESSÕES
// ─────────────────────────────────────────
const sessoes      = new Map(); // tokens de importação
const sessoesAdmin = new Map(); // tokens de gestão de usuários

const TOKEN_EXPIRY_MS = 8 * 60 * 60 * 1000;

function gerarToken() {
  return crypto.randomBytes(32).toString("hex");
}

// KDF seguro com scrypt
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

// Middleware: token de importação
function verificarToken(req, res, next) {
  const auth  = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token || !sessoes.has(token)) {
    return res.status(401).json({ erro: "Não autorizado." });
  }

  const sessao = sessoes.get(token);
  if (Date.now() > sessao.expira) {
    sessoes.delete(token);
    return res.status(401).json({ erro: "Sessão expirada." });
  }

  next();
}

// Middleware: token de gestão de usuários (super-admin)
function verificarTokenAdmin(req, res, next) {
  const auth  = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token || !sessoesAdmin.has(token)) {
    return res.status(401).json({ erro: "Não autorizado." });
  }

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
  return String(valor).trim();
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

    // Cria usuário inicial de importação a partir das variáveis de ambiente,
    // caso a coleção esteja vazia.
    const totalUsuarios = await db.collection("usuarios_importacao").countDocuments();
    if (totalUsuarios === 0 && process.env.ADMIN_USER && process.env.ADMIN_PASSWORD) {
      await db.collection("usuarios_importacao").insertOne({
        usuario:   process.env.ADMIN_USER,
        senha:     hashSenha(process.env.ADMIN_PASSWORD),
        criadoEm: new Date()
      });
      console.log(`👤 Usuário inicial criado: ${process.env.ADMIN_USER}`);
    }

    app.get("/", (req, res) => {
      res.sendFile(path.join(frontendPath, "index.html"));
    });

    // ─────────────────────────────────────
    // LOGIN / LOGOUT (área de importação)
    // ─────────────────────────────────────
    app.post("/api/login", async (req, res) => {
      const { usuario, senha } = req.body;

      if (!usuario || !senha) {
        return res.status(401).json({ erro: "Usuário ou senha inválidos." });
      }

      try {
        const user = await db.collection("usuarios_importacao").findOne({ usuario });
        if (!user || !verificarSenha(senha, user.senha)) {
          return res.status(401).json({ erro: "Usuário ou senha inválidos." });
        }

        const token = gerarToken();
        sessoes.set(token, { expira: Date.now() + TOKEN_EXPIRY_MS });
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
    // LOGIN / LOGOUT (gestão de usuários)
    // ─────────────────────────────────────
    app.post("/api/admin/login", (req, res) => {
      const { usuario, senha } = req.body;

      if (
        usuario === process.env.ADMIN_USER &&
        senha   === process.env.ADMIN_PASSWORD
      ) {
        const token = gerarToken();
        sessoesAdmin.set(token, { expira: Date.now() + TOKEN_EXPIRY_MS });
        return res.json({ token });
      }

      res.status(401).json({ erro: "Usuário ou senha inválidos." });
    });

    app.post("/api/admin/logout", (req, res) => {
      const auth  = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (token) sessoesAdmin.delete(token);
      res.json({ ok: true });
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
      const { usuario, senha } = req.body;
      if (!usuario || !senha) {
        return res.status(400).json({ erro: "Usuário e senha são obrigatórios." });
      }

      try {
        const existente = await db.collection("usuarios_importacao").findOne({ usuario });
        if (existente) {
          return res.status(400).json({ erro: "Usuário já existe." });
        }

        await db.collection("usuarios_importacao").insertOne({
          usuario,
          senha:    hashSenha(senha),
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
      if (!senha) {
        return res.status(400).json({ erro: "Nova senha é obrigatória." });
      }

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

    // ─────────────────────────────────────
    // CONSULTAS
    // ─────────────────────────────────────
    app.get("/api/dados-brutos", async (req, res) => {
      try {
        const limite = Number(req.query.limite || 5000);

        const dados = await db
          .collection("dados_brutos")
          .find({})
          .limit(limite)
          .toArray();

        res.json(dados);
      } catch (error) {
        res.status(500).json({
          erro: "Erro ao buscar dados brutos",
          detalhe: error.message
        });
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
                      in: {
                        $getField: {
                          field: "NOME PRODUTO",
                          input: "$$cat"
                        }
                      }
                    }
                  },
                  0
                ]
              },
              Nome_Loja_DePara: { $arrayElemAt: ["$loja_info.Nome_Fantasia", 0] }
            }
          },
          {
            $project: {
              categoria_info: 0,
              loja_info: 0
            }
          }
        ]).toArray();

        res.json(dados);
      } catch (error) {
        res.status(500).json({
          erro: "Erro ao buscar dados tratados",
          detalhe: error.message
        });
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

              total_vendido: {
                $sum: {
                  $toDouble: {
                    $ifNull: ["$Venda Pdv Quantidade", 0]
                  }
                }
              },

              total_valor: {
                $sum: {
                  $toDouble: {
                    $ifNull: ["$Venda Pdv Valor", 0]
                  }
                }
              },

              lojas: {
                $addToSet: "$Loja"
              }
            }
          },
          {
            $project: {
              _id: 0,
              total_vendido: 1,
              total_valor: 1,
              total_lojas: {
                $size: "$lojas"
              }
            }
          }
        ];

        const resultado = await db
          .collection("dados_brutos")
          .aggregate(pipeline)
          .toArray();

        res.json(
          resultado[0] || {
            total_vendido: 0,
            total_valor: 0,
            total_lojas: 0
          }
        );

      } catch (error) {
        res.status(500).json({
          erro: "Erro ao gerar resumo",
          detalhe: error.message
        });
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
              total_venda: {
                $sum: {
                  $toDouble: {
                    $ifNull: ["$Venda Pdv Valor", 0]
                  }
                }
              }
            }
          },
          {
            $sort: {
              total_venda: -1
            }
          },
          {
            $limit: 20
          }
        ]).toArray();

        res.json(resultado);
      } catch (error) {
        res.status(500).json({
          erro: "Erro ao buscar vendas por filial",
          detalhe: error.message
        });
      }
    });

    // ─────────────────────────────────────
    // CATEGORIAS
    // ─────────────────────────────────────
    app.get("/api/dashboard/categorias", async (req, res) => {
      try {
        const resultado = await db.collection("categorias_depara").aggregate([
          {
            $group: {
              _id: "$CATEGORIA",
              total: { $sum: 1 }
            }
          },
          {
            $sort: {
              total: -1
            }
          }
        ]).toArray();

        res.json(resultado);
      } catch (error) {
        res.status(500).json({
          erro: "Erro ao buscar categorias",
          detalhe: error.message
        });
      }
    });

    // ─────────────────────────────────────
    // FAMÍLIAS
    // ─────────────────────────────────────
    app.get("/api/dashboard/familias", async (req, res) => {
      try {
        const resultado = await db.collection("categorias_depara").aggregate([
          {
            $group: {
              _id: "$FAMILIA",
              total: { $sum: 1 }
            }
          },
          {
            $sort: {
              total: -1
            }
          }
        ]).toArray();

        res.json(resultado);
      } catch (error) {
        res.status(500).json({
          erro: "Erro ao buscar famílias",
          detalhe: error.message
        });
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
              _id: "$Data",
              total_venda: {
                $sum: {
                  $toDouble: {
                    $ifNull: ["$Venda Pdv Valor", 0]
                  }
                }
              }
            }
          },
          {
            $sort: {
              _id: 1
            }
          }
        ]).toArray();

        res.json(resultado);
      } catch (error) {
        res.status(500).json({
          erro: "Erro ao buscar vendas por dia",
          detalhe: error.message
        });
      }
    });

    // ─────────────────────────────────────
    // IMPORTAÇÕES (PROTEGIDAS)
    // ─────────────────────────────────────
    app.post(
      "/api/importar/dados-brutos",
      verificarToken,
      upload.single("file"),
      async (req, res) => {
        const resultados = [];

        if (!req.file) {
          return res.status(400).json({ erro: "Nenhum arquivo enviado." });
        }

        fs.createReadStream(req.file.path)
          .pipe(csv({ separator: ";" }))
          .on("data", (linha) => {
            const registro = {};

            Object.keys(linha).forEach((coluna) => {
              const nomeColuna = limparValor(coluna);
              registro[nomeColuna] = limparValor(linha[coluna]);
            });

            registro.importado_em = new Date();
            resultados.push(registro);
          })
          .on("end", async () => {
            if (resultados.length > 0) {
              await db.collection("dados_brutos").insertMany(resultados);
            }

            fs.unlinkSync(req.file.path);

            res.json({
              mensagem: "Importação realizada 🚀",
              total: resultados.length
            });
          });
      }
    );

    app.post(
      "/api/importar/categorias-depara",
      verificarToken,
      upload.single("file"),
      async (req, res) => {
        const resultados = [];

        fs.createReadStream(req.file.path)
          .pipe(csv({ separator: ";" }))
          .on("data", (linha) => {
            const registro = {};
            Object.keys(linha).forEach((coluna) => {
              registro[coluna.trim()] = linha[coluna].trim();
            });
            resultados.push(registro);
          })
          .on("end", async () => {
            await db.collection("categorias_depara").deleteMany({});
            await db.collection("categorias_depara").insertMany(resultados);

            res.json({ mensagem: "Categorias importadas" });
          });
      }
    );

    app.post(
      "/api/importar/lojas-depara",
      verificarToken,
      upload.single("file"),
      async (req, res) => {
        const resultados = [];

        fs.createReadStream(req.file.path)
          .pipe(csv({ separator: ";" }))
          .on("data", (linha) => {
            const registro = {};
            Object.keys(linha).forEach((coluna) => {
              registro[coluna.trim()] = linha[coluna].trim();
            });
            resultados.push(registro);
          })
          .on("end", async () => {
            await db.collection("lojas_depara").deleteMany({});
            await db.collection("lojas_depara").insertMany(resultados);

            res.json({ mensagem: "Lojas importadas" });
          });
      }
    );

    // ─────────────────────────────────────
    app.listen(PORT, () => {
      console.log(`🚀 Servidor rodando na porta ${PORT}`);
    });

  } catch (erro) {
    console.error("❌ Erro ao iniciar servidor:", erro);
  }
}

iniciarServidor();
