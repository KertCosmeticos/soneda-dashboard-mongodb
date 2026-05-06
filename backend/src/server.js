require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient } = require("mongodb");
const path = require("path");

const app = express();

app.use(cors());
app.use(express.json());

// SERVIR FRONTEND
const frontendPath = path.resolve(__dirname, "../../frontend");
app.use(express.static(frontendPath));

// CONFIG
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || "soneda";
const COLLECTION_NAME = process.env.COLLECTION_NAME || "dados";

if (!MONGO_URI) {
  console.error("❌ MONGO_URI não definida.");
  process.exit(1);
}

let db;
let collection;

async function conectarMongo() {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();

    db = client.db(DB_NAME);
    collection = db.collection(COLLECTION_NAME);

    console.log("✅ MongoDB conectado");
    console.log(`📦 Banco: ${DB_NAME}`);
    console.log(`📄 Coleção: ${COLLECTION_NAME}`);
  } catch (err) {
    console.error("❌ Erro ao conectar MongoDB:", err);
    process.exit(1);
  }
}

conectarMongo();

// HEALTHCHECK
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    api: "Soneda Dashboard MongoDB",
  });
});

// RESUMO DASHBOARD
app.get("/api/dashboard/resumo", async (req, res) => {
  try {
    const pipeline = [
      {
        $group: {
          _id: null,
          total_vendido: {
            $sum: {
              $toDouble: {
                $ifNull: ["$Venda Pdv Quantidade", 0],
              },
            },
          },
          total_valor: {
            $sum: {
              $toDouble: {
                $ifNull: ["$Venda Pdv Valor", 0],
              },
            },
          },
          lojas: {
            $addToSet: "$Loja",
          },
        },
      },
      {
        $project: {
          _id: 0,
          total_vendido: 1,
          total_valor: 1,
          total_lojas: {
            $size: "$lojas",
          },
        },
      },
    ];

    const resultado = await collection.aggregate(pipeline).toArray();

    res.json(
      resultado[0] || {
        total_vendido: 0,
        total_valor: 0,
        total_lojas: 0,
      }
    );
  } catch (err) {
    console.error("❌ Erro /api/dashboard/resumo:", err);
    res.status(500).json({
      erro: "Erro ao gerar resumo",
      detalhe: err.message,
    });
  }
});

// DADOS BRUTOS
app.get("/api/dados-brutos", async (req, res) => {
  try {
    const limite = Number(req.query.limite || 5000);

    const dados = await collection
      .find({})
      .limit(limite)
      .toArray();

    res.json(dados);
  } catch (err) {
    console.error("❌ Erro /api/dados-brutos:", err);
    res.status(500).json({
      erro: "Erro ao buscar dados brutos",
      detalhe: err.message,
    });
  }
});

// LOJAS DE/PARA
app.get("/api/lojas-depara", async (req, res) => {
  try {
    const dados = await db.collection("lojas_depara").find({}).toArray();
    res.json(dados);
  } catch (err) {
    res.status(500).json({
      erro: "Erro ao buscar lojas de/para",
      detalhe: err.message,
    });
  }
});

// CATEGORIAS DE/PARA
app.get("/api/categorias-depara", async (req, res) => {
  try {
    const dados = await db.collection("categorias_depara").find({}).toArray();
    res.json(dados);
  } catch (err) {
    res.status(500).json({
      erro: "Erro ao buscar categorias de/para",
      detalhe: err.message,
    });
  }
});

// SELL OUT OTIMIZADO
app.get("/api/vendas-sellout", async (req, res) => {
  try {
    const { dataInicio, dataFim, loja, categoria, limite } = req.query;

    const filtro = {};

    if (dataInicio || dataFim) {
      filtro.Data = {};
      if (dataInicio) filtro.Data.$gte = dataInicio;
      if (dataFim) filtro.Data.$lte = dataFim;
    }

    if (loja) filtro.Loja = loja;
    if (categoria) filtro.Categoria = categoria;

    const maxLimite = Number(limite || 5000);

    const dados = await collection
      .find(filtro)
      .limit(maxLimite)
      .toArray();

    res.json(dados);
  } catch (err) {
    console.error("❌ Erro /api/vendas-sellout:", err);
    res.status(500).json({
      erro: "Erro ao carregar sell out",
      detalhe: err.message,
    });
  }
});

// FRONTEND COMO ROTA FINAL
app.use((req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// INICIAR
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});