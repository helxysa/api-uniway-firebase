const express = require("express");
const admin = require("firebase-admin");
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();

const app = express();

const firebaseConfig = {
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY ?  
    JSON.parse(process.env.FIREBASE_PRIVATE_KEY) : undefined,
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
    universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
};
  
if (!firebaseConfig.private_key) {
    console.error('Erro: FIREBASE_PRIVATE_KEY não está configurada corretamente');
    process.exit(1);
}
  
try {
    admin.initializeApp({
      credential: admin.credential.cert(firebaseConfig),
    });
    console.log('Firebase inicializado com sucesso');
} catch (error) {
    console.error('Erro ao inicializar Firebase:', error);
    process.exit(1);
}

const db = admin.firestore();

app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

app.get('/', (req, res) => {
  res.json({ 
    success: true,
    message: 'API está funcionando!' 
  });
});

app.post("/api/users", async (req, res) => {
  try {
    const { name, email, course, password } = req.body;

    if (!name || !email || !course || !password) {
      return res.status(400).json({
        success: false,
        error: "Todos os campos são obrigatórios"
      });
    }

    const usersRef = db.collection("users");
    
    const emailCheck = await usersRef.where("email", "==", email).get();
    
    if (!emailCheck.empty) {
      return res.status(409).json({
        success: false,
        error: "Email já cadastrado"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      name,
      email,
      course,
      password: hashedPassword,
      saved: [],
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await usersRef.add(newUser);
    const { password: _, ...userWithoutPassword } = newUser;

    return res.status(201).json({
      success: true,
      message: "Usuário criado com sucesso",
      user: {
        id: docRef.id,
        ...userWithoutPassword
      }
    });

  } catch (error) {
    console.error("Erro ao processar requisição:", error);
    return res.status(500).json({
      success: false,
      error: "Erro interno do servidor"
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: "Email e senha são obrigatórios"
      });
    }

    const usersRef = db.collection("users");
    
    const userQuery = await usersRef.where("email", "==", email).get();

    if (userQuery.empty) {
      return res.status(401).json({
        success: false,
        error: "Usuário não encontrado"
      });
    }

    const userDoc = userQuery.docs[0];
    const userData = userDoc.data();

    const passwordMatch = await bcrypt.compare(password, userData.password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        error: "Senha incorreta"
      });
    }

    const { password: _, ...userWithoutPassword } = userData;

    return res.status(200).json({
      success: true,
      message: "Login realizado com sucesso",
      user: {
        id: userDoc.id,
        ...userWithoutPassword
      }
    });

  } catch (error) {
    console.error("Erro ao processar login:", error);
    return res.status(500).json({
      success: false,
      error: "Erro interno do servidor"
    });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const usersRef = db.collection("users");
    const snapshot = await usersRef.get();
    
    const users = [];
    snapshot.forEach(doc => {
      const userData = doc.data();
      const { password, ...userWithoutPassword } = userData;
      users.push({
        id: doc.id,
        ...userWithoutPassword
      });
    });

    return res.status(200).json({
      success: true,
      users
    });

  } catch (error) {
    console.error("Erro ao buscar usuários:", error);
    return res.status(500).json({
      success: false,
      error: "Erro ao buscar usuários"
    });
  }
});

app.get("/api/users/:id", async (req, res) => {
  try {
    const userId = req.params.id;
    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: "Usuário não encontrado"
      });
    }

    const userData = userDoc.data();
    const { password, ...userWithoutPassword } = userData;

    return res.status(200).json({
      success: true,
      user: {
        id: userDoc.id,
        ...userWithoutPassword
      }
    });

  } catch (error) {
    console.error("Erro ao buscar usuário:", error);
    return res.status(500).json({
      success: false,
      error: "Erro ao buscar usuário"
    });
  }
});

app.put("/api/users/:id", async (req, res) => {
  try {
    const userId = req.params.id;
    const { name, email, course, password } = req.body;

    const userRef = db.collection("users").doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: "Usuário não encontrado"
      });
    }

    const updateData = {
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (course) updateData.course = course;
    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    }

    await userRef.update(updateData);

    const updatedDoc = await userRef.get();
    const updatedData = updatedDoc.data();
    const { password: _, ...userWithoutPassword } = updatedData;

    return res.status(200).json({
      success: true,
      message: "Usuário atualizado com sucesso",
      user: {
        id: userId,
        ...userWithoutPassword
      }
    });

  } catch (error) {
    console.error("Erro ao atualizar usuário:", error);
    return res.status(500).json({
      success: false,
      error: "Erro ao atualizar usuário"
    });
  }
});

app.delete("/api/users/:id", async (req, res) => {
  try {
    const userId = req.params.id;
    const userRef = db.collection("users").doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: "Usuário não encontrado"
      });
    }

    await userRef.delete();

    return res.status(200).json({
      success: true,
      message: "Usuário deletado com sucesso"
    });

  } catch (error) {
    console.error("Erro ao deletar usuário:", error);
    return res.status(500).json({
      success: false,
      error: "Erro ao deletar usuário"
    });
  }
});

// Novos endpoints para gerenciar vagas salvas
app.post("/api/users/:userId/saved/:vagaId", async (req, res) => {
  try {
    const { userId, vagaId } = req.params;
    
    const userRef = db.collection("users").doc(userId);
    const vagaRef = db.collection("vagas").doc(vagaId);
    
    const [userDoc, vagaDoc] = await Promise.all([
      userRef.get(),
      vagaRef.get()
    ]);

    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: "Usuário não encontrado"
      });
    }

    if (!vagaDoc.exists) {
      return res.status(404).json({
        success: false,
        error: "Vaga não encontrada"
      });
    }

    const userData = userDoc.data();
    const saved = userData.saved || [];

    if (saved.includes(vagaId)) {
      return res.status(400).json({
        success: false,
        error: "Vaga já está salva"
      });
    }

    await userRef.update({
      saved: admin.firestore.FieldValue.arrayUnion(vagaId),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.status(200).json({
      success: true,
      message: "Vaga salva com sucesso"
    });

  } catch (error) {
    console.error("Erro ao salvar vaga:", error);
    return res.status(500).json({
      success: false,
      error: "Erro ao salvar vaga"
    });
  }
});

app.delete("/api/users/:userId/saved/:vagaId", async (req, res) => {
  try {
    const { userId, vagaId } = req.params;
    
    const userRef = db.collection("users").doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: "Usuário não encontrado"
      });
    }

    const userData = userDoc.data();
    const saved = userData.saved || [];

    if (!saved.includes(vagaId)) {
      return res.status(400).json({
        success: false,
        error: "Vaga não está salva"
      });
    }

    await userRef.update({
      saved: admin.firestore.FieldValue.arrayRemove(vagaId),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.status(200).json({
      success: true,
      message: "Vaga removida dos salvos com sucesso"
    });

  } catch (error) {
    console.error("Erro ao remover vaga dos salvos:", error);
    return res.status(500).json({
      success: false,
      error: "Erro ao remover vaga dos salvos"
    });
  }
});

app.get("/api/users/:userId/saved", async (req, res) => {
  try {
    const { userId } = req.params;
    
    const userRef = db.collection("users").doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: "Usuário não encontrado"
      });
    }

    const userData = userDoc.data();
    const saved = userData.saved || [];

    if (saved.length === 0) {
      return res.status(200).json({
        success: true,
        vagas: []
      });
    }

    const vagasRef = db.collection("vagas");
    const vagasDocs = await Promise.all(
      saved.map(vagaId => vagasRef.doc(vagaId).get())
    );

    const vagas = vagasDocs
      .filter(doc => doc.exists)
      .map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

    return res.status(200).json({
      success: true,
      vagas
    });

  } catch (error) {
    console.error("Erro ao buscar vagas salvas:", error);
    return res.status(500).json({
      success: false,
      error: "Erro ao buscar vagas salvas"
    });
  }
});

app.post("/api/vagas", async (req, res) => {
    try {
      const { titulo, empresa, descricao, requisitos, salario, localizacao, tipo_contrato, curso } = req.body;
  
      if (!titulo || !empresa || !descricao || !requisitos || !salario || !localizacao || !tipo_contrato) {
        return res.status(400).json({
          success: false,
          error: "Todos os campos são obrigatórios"
        });
      }
  
      const vagasRef = db.collection("vagas");
      
      const novaVaga = {
        titulo,
        empresa,
        descricao,
        requisitos,
        salario,
        localizacao,
        tipo_contrato,
        curso: curso || null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      };
  
      const docRef = await vagasRef.add(novaVaga);
  
      return res.status(201).json({
        success: true,
        message: "Vaga criada com sucesso",
        vaga: {
          id: docRef.id,
          ...novaVaga
        }
      });
  
    } catch (error) {
      console.error("Erro ao criar vaga:", error);
      return res.status(500).json({
        success: false,
        error: "Erro ao criar vaga"
      });
    }
});

app.get("/api/vagas", async (req, res) => {
    try {
      const vagasRef = db.collection("vagas");
      const snapshot = await vagasRef.get();
      
      const vagas = [];
      snapshot.forEach(doc => {
        vagas.push({
          id: doc.id,
          ...doc.data()
        });
      });
  
      return res.status(200).json({
        success: true,
        vagas
      });
  
    } catch (error) {
      console.error("Erro ao buscar vagas:", error);
      return res.status(500).json({
        success: false,
        error: "Erro ao buscar vagas"
      });
    }
});

app.get("/api/vagas/:id", async (req, res) => {
    try {
      const vagaId = req.params.id;
      const vagaDoc = await db.collection("vagas").doc(vagaId).get();
  
      if (!vagaDoc.exists) {
        return res.status(404).json({
          success: false,
          error: "Vaga não encontrada"
        });
      }
  
      return res.status(200).json({
        success: true,
        vaga: {
          id: vagaDoc.id,
          ...vagaDoc.data()
        }
      });
  
    } catch (error) {
      console.error("Erro ao buscar vaga:", error);
      return res.status(500).json({
        success: false,
        error: "Erro ao buscar vaga"
      });
    }
});

app.put("/api/vagas/:id", async (req, res) => {
    try {
      const vagaId = req.params.id;
      const { titulo, empresa, descricao, requisitos, salario, localizacao, tipo_contrato, curso } = req.body;
  
      const vagaRef = db.collection("vagas").doc(vagaId);
      const vagaDoc = await vagaRef.get();
  
      if (!vagaDoc.exists) {
        return res.status(404).json({
          success: false,
          error: "Vaga não encontrada"
        });
      }
  
      const updateData = {
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      };
  
      if (titulo) updateData.titulo = titulo;
      if (empresa) updateData.empresa = empresa;
      if (descricao) updateData.descricao = descricao;
      if (requisitos) updateData.requisitos = requisitos;
      if (salario) updateData.salario = salario;
      if (localizacao) updateData.localizacao = localizacao;
      if (tipo_contrato) updateData.tipo_contrato = tipo_contrato;
      if (curso !== undefined) updateData.curso = curso;
  
      await vagaRef.update(updateData);
  
      const updatedDoc = await vagaRef.get();
  
      return res.status(200).json({
        success: true,
        message: "Vaga atualizada com sucesso",
        vaga: {
          id: vagaId,
          ...updatedDoc.data()
        }
      });
  
    } catch (error) {
      console.error("Erro ao atualizar vaga:", error);
      return res.status(500).json({
        success: false,
        error: "Erro ao atualizar vaga"
      });
    }
});

app.delete("/api/vagas/:id", async (req, res) => {
    try {
      const vagaId = req.params.id;
      const vagaRef = db.collection("vagas").doc(vagaId);
      const vagaDoc = await vagaRef.get();
  
      if (!vagaDoc.exists) {
        return res.status(404).json({
          success: false,
          error: "Vaga não encontrada"
        });
      }
  
      await vagaRef.delete();
  
      return res.status(200).json({
        success: true,
        message: "Vaga deletada com sucesso"
      });
  
    } catch (error) {
      console.error("Erro ao deletar vaga:", error);
      return res.status(500).json({
        success: false,
        error: "Erro ao deletar vaga"
      });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});