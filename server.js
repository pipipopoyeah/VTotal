const express = require('express');
const fetch = require('node-fetch');
const app = express();

const VIRUSTOTAL_API_KEY = '85cf97a6b2db72efc28aa90d39a79e24740bbcc231e99ce46ed41f79b0140490';

app.use(express.json());
app.use(express.static('public'));

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
      return res.status(response.status).json({ error: `Error in VirusTotal request: ${response.status}` });
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Error processing the hash' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
