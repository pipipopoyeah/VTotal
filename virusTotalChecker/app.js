const express = require('express');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
  res.render('index', { results: { block: [], noBlock: [], invalid: [], undetected: [] } });
});

app.post('/check-hashes', async (req, res) => {
  const { hashes } = req.body;
  const hashList = hashes.split('\n').map(hash => hash.trim()).filter(hash => hash);
  const results = { block: [], noBlock: [], invalid: [], undetected: [] };

  for (const hash of hashList) {
    if (!/^[a-f0-9]{32,64}$/i.test(hash)) {
      results.invalid.push(hash);
      continue;
    }

    try {
      const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      });

      const analysisResults = response.data.data.attributes.last_analysis_results;
      let mcafeeUndetected = true;
      let mcafeeFound = false;
      let isDetectedByAnyVendor = false;

      for (let vendor in analysisResults) {
        if (vendor.toLowerCase().includes('mcafee')) {
          mcafeeFound = true;
          const result = analysisResults[vendor].result;
          const category = analysisResults[vendor].category;
          if (category === 'undetected' || result === 'Unable to process file type') {
            mcafeeUndetected = true;
          } else {
            mcafeeUndetected = false;
            break;
          }
        }
        if (analysisResults[vendor].category !== 'undetected' && analysisResults[vendor].category !== 'type-unsupported') {
          isDetectedByAnyVendor = true;
        }
      }

      if (!mcafeeFound || mcafeeUndetected) {
        results.block.push(hash);
      } else {
        results.noBlock.push(hash);
      }

      if (!isDetectedByAnyVendor) {
        results.undetected.push(hash);
      }

    } catch (error) {
      results.invalid.push(hash);
    }
  }

  res.render('index', { results });
});

app.post('/clear-results', (req, res) => {
  res.render('index', { results: { block: [], noBlock: [], invalid: [], undetected: [] } });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
