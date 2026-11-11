const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const app = express();
app.use(cors());
app.use(express.json());

const SECRET = 'change_this_secret'; // à mettre dans un .env plus tard
const db = mysql.createPool({ host: 'localhost', user: 'root', password: '', database: 'rental_management' });

// Boîte mail de test (facultative : si elle échoue, le code s'affiche dans le terminal)
let mailer;
nodemailer.createTestAccount()
  .then((a) => {
    mailer = nodemailer.createTransport({ host: a.smtp.host, port: a.smtp.port, secure: a.smtp.secure, auth: { user: a.user, pass: a.pass } });
  })
  .catch(() => console.log("Boîte mail de test indisponible : les codes s'afficheront ici."));

const sign = (id, roles) => jwt.sign({ id, roles }, SECRET, { expiresIn: '2h' });

const toRoles = (r) => {
  const roles = Array.isArray(r) ? r : [r];
  return roles.length && roles.every((x) => ['proprietaire', 'locataire'].includes(x)) ? roles : null;
};

// Gère les erreurs de toutes les routes au même endroit
const route = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    if (e.code === 'ER_DUP_ENTRY') return res.status(400).json({ erreur: 'Cet email est déjà utilisé.' });
    console.error(e);
    res.status(500).json({ erreur: 'Erreur serveur.' });
  });

// Vérifie le token de l'utilisateur connecté
const auth = (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], SECRET);
    next();
  } catch {
    res.status(401).json({ erreur: 'Non connecté.' });
  }
};

// Réservé aux propriétaires connectés
const owner = (req, res, next) =>
  req.user.roles.includes('proprietaire') ? next() : res.status(403).json({ erreur: 'Réservé aux propriétaires.' });

app.get('/api/test', (req, res) => res.json({ message: 'Le serveur fonctionne !' }));

// ---------------- AUTHENTIFICATION ----------------
app.post('/api/auth/register', route(async (req, res) => {
  const { nom, email, mot_de_passe, role } = req.body;
  const roles = toRoles(role);
  if (!nom || !email || !mot_de_passe || !role) return res.status(400).json({ erreur: 'Tous les champs sont obligatoires.' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ erreur: 'Email invalide.' });
  if (mot_de_passe.length < 8) return res.status(400).json({ erreur: 'Mot de passe trop court (8 caractères minimum).' });
  if (mot_de_passe.toLowerCase() === email.toLowerCase()) return res.status(400).json({ erreur: "Le mot de passe ne doit pas être identique à l'email." });
  if (!roles) return res.status(400).json({ erreur: 'Rôle invalide.' });

  const hash = await bcrypt.hash(mot_de_passe, 10);
  const code = String(crypto.randomInt(100000, 1000000));
  await db.query(
    'INSERT INTO users (nom, email, mot_de_passe, role, code_verification, code_expiration) VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
    [nom, email, hash, roles.join(','), code]
  );

  console.log(`Code de vérification pour ${email} : ${code}`);
  mailer?.sendMail({ from: 'no-reply@rental.com', to: email, subject: 'Code de vérification', text: `Votre code : ${code}` }).catch(() => {});

  res.status(201).json({ message: 'Inscription réussie ! Vérifiez votre email.' });
}));

app.post('/api/auth/verify', route(async (req, res) => {
  const { email, code } = req.body;
  const [r] = await db.query(
    'UPDATE users SET verifie = 1, code_verification = NULL WHERE email = ? AND code_verification = ? AND code_expiration > NOW()',
    [email, code]
  );
  if (!r.affectedRows) return res.status(400).json({ erreur: 'Code invalide ou expiré.' });
  res.json({ message: 'Email vérifié.' });
}));

app.post('/api/auth/login', route(async (req, res) => {
  const { email, mot_de_passe } = req.body;
  const [[u]] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
  if (!u || !(await bcrypt.compare(mot_de_passe, u.mot_de_passe))) return res.status(401).json({ erreur: 'Email ou mot de passe incorrect.' });
  if (!u.verifie) return res.status(403).json({ erreur: 'Email non vérifié.' });
  const roles = u.role.split(',');
  res.json({ message: 'Connexion réussie.', token: sign(u.id, roles), roles });
}));

app.put('/api/auth/roles', auth, route(async (req, res) => {
  const roles = toRoles(req.body.roles);
  if (!roles) return res.status(400).json({ erreur: 'Rôle invalide.' });
  await db.query('UPDATE users SET role = ? WHERE id = ?', [roles.join(','), req.user.id]);
  res.json({ message: 'Rôles mis à jour.', token: sign(req.user.id, roles), roles });
}));

// ---------------- BIENS IMMOBILIERS ----------------
app.get('/api/properties', route(async (req, res) => {
  const [rows] = await db.query('SELECT * FROM properties');
  res.json(rows);
}));

app.post('/api/properties', auth, owner, route(async (req, res) => {
  const { titre, adresse, prix, description } = req.body;
  if (!titre || !adresse || !(prix > 0)) return res.status(400).json({ erreur: 'Titre, adresse et prix valides obligatoires.' });
  const [r] = await db.query('INSERT INTO properties (owner_id, titre, adresse, prix, description) VALUES (?, ?, ?, ?, ?)', [req.user.id, titre, adresse, prix, description || null]);
  res.status(201).json({ message: 'Bien ajouté.', id: r.insertId });
}));

app.put('/api/properties/:id', auth, owner, route(async (req, res) => {
  const { titre, adresse, prix, description, statut } = req.body;
  if (statut && !['libre', 'loue'].includes(statut)) return res.status(400).json({ erreur: 'Statut invalide (libre ou loue).' });
  const [r] = await db.query(
    'UPDATE properties SET titre = COALESCE(?, titre), adresse = COALESCE(?, adresse), prix = COALESCE(?, prix), description = COALESCE(?, description), statut = COALESCE(?, statut) WHERE id = ? AND owner_id = ?',
    [titre, adresse, prix, description, statut, req.params.id, req.user.id]
  );
  if (!r.affectedRows) return res.status(404).json({ erreur: 'Bien introuvable.' });
  res.json({ message: 'Bien modifié.' });
}));

app.delete('/api/properties/:id', auth, owner, route(async (req, res) => {
  const [r] = await db.query('DELETE FROM properties WHERE id = ? AND owner_id = ?', [req.params.id, req.user.id]);
  if (!r.affectedRows) return res.status(404).json({ erreur: 'Bien introuvable.' });
  res.json({ message: 'Bien supprimé.' });
}));

app.listen(5000, () => console.log('Serveur lancé sur http://localhost:5000'));  
  