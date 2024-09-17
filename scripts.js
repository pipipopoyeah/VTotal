// Inserta tu API key aquí
const VIRUSTOTAL_API_KEY = '85cf97a6b2db72efc28aa90d39a79e24740bbcc231e99ce46ed41f79b0140490';
let vendorInfoByHash = {}; // Objeto para almacenar la información de los vendors por hash

document.getElementById('hashForm').addEventListener('submit', async function(event) {
  event.preventDefault();

  const hashes = document.getElementById('hashes').value.split('\n').map(hash => hash.trim()).filter(hash => hash);
  const results = { block: [], noBlock: [], invalid: [], undetected: [] };
  vendorInfoByHash = {}; // Reinicia la información de los vendors por hash

  for (const hash of hashes) {
    if (!/^[a-f0-9]{32,64}$/i.test(hash)) {
      if (!results.invalid.includes(hash)) { // Verifica si ya está en la lista
        results.invalid.push(hash); // Solo se agrega si no está
      }
      continue;
    }

    try {
      // Verifica si el hash es MD5, SHA-1 o SHA-256
      const hashLength = hash.length;
      let url;

      if (hashLength === 32 || hashLength === 40 || hashLength === 64) {
        // La API acepta MD5, SHA-1 y SHA-256
        url = `https://www.virustotal.com/api/v3/files/${hash}`;
      } else {
        if (!results.invalid.includes(hash)) {
          results.invalid.push(hash); // Si no es de estos tipos, lo tratamos como inválido
        }
        continue;
      }

      const response = await fetch(url, {
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      });

      if (!response.ok) {
        throw new Error(`Error en la solicitud a VirusTotal: ${response.status}`);
      }

      const data = await response.json();

      // Si el hash ingresado es MD5 o SHA-1, obtenemos el SHA-256 desde VirusTotal
      const sha256 = data.data.id;
      const analysisResults = data.data.attributes.last_analysis_results;

      let mcafeeDetected = false;
      let mcafeeFound = false;
      let isMaliciousByOtherVendors = false;

      // Guarda la información de vendors en un array para el hash actual
      vendorInfoByHash[sha256] = []; // Inicializa el array para este hash

      for (let vendor in analysisResults) {
        const result = analysisResults[vendor].result;
        const category = analysisResults[vendor].category;

        // Formatea la información de McAfee en negrita
        if (vendor.toLowerCase().includes('mcafee')) {
          vendorInfoByHash[sha256].push(`<strong>Vendor: ${vendor}, Category: ${category}, Result: ${result || 'null'}</strong>`);
        } else {
          vendorInfoByHash[sha256].push(`Vendor: ${vendor}, Category: ${category}, Result: ${result || 'null'}`);
        }

        // Revisa si McAfee o McAfeeD detectan el hash
        if (vendor.toLowerCase().includes('mcafee')) {
          mcafeeFound = true;
          if (category === 'malicious') {
            mcafeeDetected = true;
            break; // Si McAfee lo detecta como malicioso, terminamos el ciclo
          }
        }

        // Verifica si algún otro vendor lo marca como malicioso
        if (category === 'malicious') {
          isMaliciousByOtherVendors = true;
        }
      }

      // Clasificación de acuerdo a la lógica, sin duplicados
      if (!mcafeeFound || !mcafeeDetected) {
        if (isMaliciousByOtherVendors) {
          if (!results.block.includes(sha256)) { // Evitar duplicados
            results.block.push(sha256); // Se bloquea si otro vendor lo marca como malicioso y McAfee no lo detecta como tal
          }
        } else {
          if (!results.undetected.includes(sha256)) { // Evitar duplicados
            results.undetected.push(sha256); // Si ningún vendor lo marca como malicioso, va a "Undetected by All Vendors"
          }
        }
      } else {
        if (!results.noBlock.includes(sha256)) { // Evitar duplicados
          results.noBlock.push(sha256); // Si McAfee lo detecta como malicioso, no se bloquea
        }
      }

    } catch (error) {
      if (!results.invalid.includes(hash)) { // Evitar duplicados en inválidos
        results.invalid.push(hash); // Si ocurre un error, se considera inválido
      }
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
    console.error('No se pudo copiar el texto: ', err);
  });
}

// Función para abrir el popup del ojo
function openVendorInfoPopup() {
  const vendorInfoElement = document.getElementById('vendorInfo');
  vendorInfoElement.innerHTML = ''; // Limpiamos el contenido del popup

  // Recorre los hashes y agrega la información de los vendors
  for (let hash in vendorInfoByHash) {
    vendorInfoElement.innerHTML += `<strong>Hash: ${hash}</strong><br>`;
    vendorInfoByHash[hash].forEach(info => {
      vendorInfoElement.innerHTML += `${info}<br>`;
    });
    vendorInfoElement.innerHTML += '<hr>'; // Separador entre hashes
  }

  document.getElementById('vendorInfoPopup').style.display = 'block';
}

// Función para cerrar el popup del ojo
function closeVendorInfoPopup() {
  document.getElementById('vendorInfoPopup').style.display = 'none';
}

// Cerrar el popup al hacer clic fuera del popup
window.addEventListener('click', function(event) {
  const popup = document.getElementById('vendorInfoPopup');
  if (event.target === popup) {
    closeVendorInfoPopup();
  }
});

// Cerrar el popup al presionar la tecla ESC
window.addEventListener('keydown', function(event) {
  if (event.key === 'Escape') {
    closeVendorInfoPopup();
  }
});

// Asegurarse de que el botón del ojo funcione
document.getElementById('eyeButton').addEventListener('click', openVendorInfoPopup);
