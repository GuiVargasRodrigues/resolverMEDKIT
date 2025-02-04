const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require("path");
const fs = require("fs");
const formidable = require("formidable");
const db = require('./dbConfig');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const SECRET_KEY = 'segredo';

// Middleware para autenticação de token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.post('/cadastro', async (req, res) => {
    const { nome, cpf, senha, dataNascimento, genero, email, telefone, endereco } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(senha, 10);

        db.query(
            'INSERT INTO usuarios (cpf, senha, nome, data_nascimento, genero, email, telefone, endereco_completo) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [cpf, hashedPassword, nome, dataNascimento, genero, email, telefone, endereco],
            (err, result) => {
                if (err) {
                    console.log(err); // LOG DO ERRO NO CONSOLE
                    return res.status(500).send('Erro ao registrar usuário.');
                }
                res.sendStatus(201);
            }
        );
    } catch (error) {
        console.log(error); // LOG DO ERRO NO CONSOLE
        res.status(500).send('Erro interno do servidor.');
    }
});

app.post('/login', async (req, res) => {
    const { cpf, senha } = req.body;

    console.log('Tentativa de login com CPF:', cpf);

    // Busca o usuário pelo CPF
    const query = 'SELECT * FROM usuarios WHERE cpf = ?';
    db.query(query, [cpf], async (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Erro no servidor.' });
        }

        if (results.length === 0) {
            return res.status(400).json({ success: false, message: 'Usuário ou senha incorretos!' });
        }

        const user = results[0];

        // Verifica se a senha está correta
        const passwordMatch = await bcrypt.compare(senha, user.senha);
        
        if (!passwordMatch) {
            return res.status(400).json({ success: false, message: 'Usuário ou senha incorretos!' });
        }

        // Gera o token JWT
        const token = jwt.sign({ id: user.id_usuario, cpf: user.cpf }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ success: true, message: 'Login bem-sucedido!', token });
    });
});

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Endpoint para salvar receitas
app.post("/receitas", (req, res) => {
    const form = new formidable.IncomingForm(); 
    form.uploadDir = uploadDir;  // Setar o diretório de upload
    form.keepExtensions = true;  // Manter a extensão original do arquivo

    form.parse(req, (err, fields, files) => {
        if (err) {
            console.error("Erro ao processar o arquivo:", err);
            return res.status(500).send("Erro ao processar o arquivo.");
        }

        const { nome_medicamento, validade, id_usuario } = fields;
        const anexo_receita = files.anexo_receita ? files.anexo_receita[0].newFilename : ''; // Obter o nome do arquivo

        if (!nome_medicamento || !validade || !id_usuario) {
            return res.status(400).send("Faltando dados obrigatórios.");
        }

        // Inserir dados no banco de dados MySQL
        db.query("INSERT INTO receitas (id_usuario, nome_medicamento, validade, anexo_receita) VALUES (?, ?, ?, ?)", 
            [id_usuario, nome_medicamento, validade, anexo_receita], 
            (err, result) => {
                if (err) {
                    console.error("Erro ao inserir no banco:", err);
                    return res.status(500).send("Erro ao salvar a receita.");
                }
                res.status(200).json({ message: "Receita salva com sucesso." });
            });
    });
});


// Endpoint para salvar histórico
app.post("/historico", (req, res) => {
    const { condicao, alergia, id_usuario } = req.body;

    if (!condicao && !alergia) {
        return res.status(400).send("É necessário fornecer ao menos uma condição ou alergia.");
    }

    db.query(
        "INSERT INTO historico (id_usuario, condicao, alergia) VALUES (?, ?, ?)",
        [id_usuario, condicao || null, alergia || null],
        (err, result) => {
            if (err) {
                console.error("Erro ao salvar no banco de dados:", err);
                return res.status(500).send("Erro ao salvar no histórico.");
            }
            res.status(200).json({ message: "Histórico salvo com sucesso." });
        }
    );
});

// Endpoint para listar receitas
app.get("/receitas", (req, res) => {
    db.query("SELECT * FROM receitas", (err, results) => {
        if (err) {
            console.error("Erro ao carregar receitas:", err);
            return res.status(500).send("Erro ao carregar receitas.");
        }
        res.status(200).json(results);
    });
});

// Endpoint para listar históricos
app.get("/historico", (req, res) => {
    db.query("SELECT * FROM alergias WHERE id_usario", (err, results) => {
        if (err) {
            console.error("Erro ao carregar históricos:", err);
            return res.status(500).send("Erro ao carregar históricos.");
        }
        res.status(200).json(results);
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando na porta 3000');
});
