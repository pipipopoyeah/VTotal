const express = require('express');
const path = require('path');

const app = express();

// Servir los archivos estáticos desde la carpeta raíz
app.use(express.static(path.join(__dirname)));

// Ruta de prueba para verificar que el servidor funciona
app.get('/ping', (req, res) => {
  res.send('Server is running');
});

// Definir el puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
