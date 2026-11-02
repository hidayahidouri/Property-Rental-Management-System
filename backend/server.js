const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/api/test', (req, res) => {
  res.json({ message: 'Le serveur fonctionne !' });
});

app.listen(5000, () => {
  console.log('Serveur lancé sur http://localhost:5000');
});