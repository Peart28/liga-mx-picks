const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Sirve el index.html y cualquier archivo estático de esta carpeta
app.use(express.static(__dirname));

// Cualquier ruta devuelve el index (single page app)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Liga MX Picks corriendo en el puerto ${PORT}`);
});
