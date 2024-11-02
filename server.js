const express = require("express");
const admin = require("firebase-admin");
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();

const app = express();

// Configuração do Firebase Admin
const firebaseConfig = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
};

admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig),
});

const db = admin.firestore();

// Middlewares
app.use(cors());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

// Rota para criar usuário
app.post("/api/users", async (req, res) => {
  try {
    const { name, email, course, password } = req.body;

    // Validações básicas
    if (!name || !email || !course || !password) {
      return res.status(400).json({
        error: "Todos os campos são obrigatórios",
      });
    }

    // Verificar se email já existe
    const usersRef = db.collection("users");
    const emailCheck = await usersRef.where("email", "==", email).get();

    if (!emailCheck.empty) {
      return res.status(400).json({
        error: "Email já cadastrado",
      });
    }

    // Criptografar senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Criar novo usuário
    const newUser = {
      name,
      email,
      course,
      password: hashedPassword,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Salvar no Firestore
    const docRef = await usersRef.add(newUser);

    // Retornar resposta sem a senha
    const { password: _, ...userWithoutPassword } = newUser;

    return res.status(201).json({
      message: "Usuário criado com sucesso",
      user: {
        id: docRef.id,
        ...userWithoutPassword,
      },
    });
  } catch (error) {
    console.error("Erro ao criar usuário:", error);
    return res.status(500).json({
      error: "Erro interno do servidor",
    });
  }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
