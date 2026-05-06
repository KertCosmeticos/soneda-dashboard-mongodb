const express = require("express");
const cors = require("cors");
const { MongoClient } = require("mongodb");
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
// AUTH (LOGIN ADM)
// ─────────────────────────────────────────
const sessoes = new Map();
const TOKEN_EXPIRY_MS = 8 * 60 * 60 * 1000;

function gerarToken() {
  return crypto.randomBytes(32).toString("hex");
}

function verificarToken(req, res, next) {
  const auth = req.headers.authorization || "";
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

    app.get("/", (req, res) => {
      res.sendFile(path.join(frontendPath, "index.html"));
    });

    // ─────────────────────────────────────
    // LOGIN / LOGOUT
    // ─────────────────────────────────────
    app.post("/api/login", (req, res) => {
      const { usuario, senha } = req.body;

      if (
        usuario === process.env.ADMIN_USER &&
        senha === process.env.ADMIN_PASSWORD
      ) {
        const token = gerarToken();
        sessoes.set(token, { expira: Date.now() + TOKEN_EXPIRY_MS });

        return res.json({ token });
      }

      res.status(401).json({ erro: "Usuário ou senha inválidos." });
    });

    app.post("/api/logout", (req, res) => {
      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

      if (token) sessoes.delete(token);

      res.json({ ok: true });
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
              Familia_DePara: { $arrayElemAt: ["$categoria_info.FAMILIA", 0] },
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