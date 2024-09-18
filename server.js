const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const app = express();

const VIRUSTOTAL_API_KEY = '85cf97a6b2db72efc28aa90d39a79e24740bbcc231e99ce46ed41f79b0140490';

app.use(express.json());

// Sirve archivos estáticos desde la carpeta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Ruta para procesar las solicitudes a VirusTotal
app.post('/api/check-hash', async (req, res) => {
  const { hash } = req.body;

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY
      }
    });

    if (!response.ok) {
      return res.status(response.status).json({ error: `Error en la solicitud a VirusTotal: ${response.status}` });
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Error procesando el hash' });
  }
});

// Ruta para servir el archivo index.html por defecto
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
