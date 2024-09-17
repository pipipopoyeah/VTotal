// Inserta tu API key aquí
const VIRUSTOTAL_API_KEY = '85cf97a6b2db72efc28aa90d39a79e24740bbcc231e99ce46ed41f79b0140490';

document.getElementById('hashForm').addEventListener('submit', async function(event) {
  event.preventDefault();

  const hashes = document.getElementById('hashes').value.split('\n').map(hash => hash.trim()).filter(hash => hash);
  const results = { block: [], noBlock: [], invalid: [], undetected: [] };

  for (const hash of hashes) {
    if (!/^[a-f0-9]{32,64}$/i.test(hash)) {
      results.invalid.push(hash);
      continue;
    }

    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      });

      if (!response.ok) {
        throw new Error(`Error in VirusTotal request: ${response.status}`);
      }

      const data = await response.json();
      const analysisResults = data.data.attributes.last_analysis_results;
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

  // Limpia las listas antes de mostrar nuevos resultados
  clearResults();

  // Muestra los resultados en las listas correspondientes
  displayResults('blockList', results.block);
  displayResults('noBlockList', results.noBlock);
  displayResults('invalidList', results.invalid);
  displayResults('undetectedList', results.undetected);
});

// Función para limpiar las listas de resultados
function clearResults() {
  document.getElementById('blockList').innerHTML = '';
  document.getElementById('noBlockList').innerHTML = '';
  document.getElementById('invalidList').innerHTML = '';
  document.getElementById('undetectedList').innerHTML = '';
}

// Función para mostrar resultados en una lista
function displayResults(listId, items) {
  const list = document.getElementById(listId);
  items.forEach(item => {
    const li = document.createElement('li');
    li.textContent = item;
    list.appendChild(li);
  });
}

// Función para limpiar los inputs
function clearInput() {
  document.getElementById('hashes').value = '';
  clearResults();
}

// Función para copiar contenido al portapapeles
function copyToClipboard(listId) {
  const list = document.getElementById(listId);
  const text = Array.from(list.children).map(li => li.textContent).join('\n');
  navigator.clipboard.writeText(text).catch(err => {
    console.error('Could not copy text: ', err);
  });
}
