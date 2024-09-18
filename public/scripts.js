console.log('Script cargado correctamente');

// Inserta tu API key aquí
const VIRUSTOTAL_API_KEY = '85cf97a6b2db72efc28aa90d39a79e24740bbcc231e99ce46ed41f79b0140490';
let vendorInfo = ''; // Variable para almacenar la información de los vendors

document.getElementById('hashForm').addEventListener('submit', async function(event) {
  event.preventDefault();

  const hashes = document.getElementById('hashes').value.split('\n').map(hash => hash.trim()).filter(hash => hash);
  const results = { block: new Set(), noBlock: new Set(), invalid: new Set(), undetected: new Set() };
  vendorInfo = ''; // Reinicia la información de los vendors

  // Eliminar duplicados de los hashes
  const uniqueHashes = [...new Set(hashes)];

  for (const hash of uniqueHashes) {
    // Validar si el hash es SHA-256 (64 caracteres hexadecimales)
    if (/^[a-f0-9]{64}$/i.test(hash)) {
      await processHash(hash, results); // Procesa el hash si es válido
    } else {
      try {
        // Intentar convertir a SHA-256 si no es un hash SHA-256 válido
        const sha256Hash = await convertToSha256(hash);
        if (!sha256Hash) {
          results.invalid.add(hash); // Agrega a la lista de inválidos si no se puede convertir
        } else {
          await processHash(sha256Hash, results); // Procesa el hash convertido
        }
      } catch (error) {
        results.invalid.add(hash); // Si hay error, lo marca como inválido
      }
    }
  }

  // Limpia las listas antes de mostrar nuevos resultados
  clearResults();

  // Muestra los resultados en las listas correspondientes
  displayResults('blockList', Array.from(results.block));
  displayResults('noBlockList', Array.from(results.noBlock));
  displayResults('invalidList', Array.from(results.invalid));
  displayResults('undetectedList', Array.from(results.undetected));
});

// Función para convertir un hash a SHA-256 usando VirusTotal
async function convertToSha256(hash) {
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY
      }
    });

    if (!response.ok) {
      throw new Error(`Error en la solicitud a VirusTotal: ${response.status}`);
    }

    const data = await response.json();
    const sha256 = data.data.id; // VirusTotal devuelve el SHA-256 en 'data.id'
    return sha256;
  } catch (error) {
    console.error('Error al convertir el hash a SHA-256:', error);
    return null;
  }
}

// Función para procesar un hash y clasificarlo en las categorías adecuadas
async function processHash(hash, results) {
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY
      }
    });

    if (!response.ok) {
      console.error(`Error en la solicitud a VirusTotal para el hash: ${hash}, status: ${response.status}`);
      throw new Error(`Error en la solicitud a VirusTotal: ${response.status}`);
    }

    const data = await response.json();
    if (!data || !data.data || !data.data.attributes || !data.data.attributes.last_analysis_results) {
      console.error(`Datos incompletos o inválidos para el hash: ${hash}`, data);
      results.invalid.add(hash);
      return;
    }

    const analysisResults = data.data.attributes.last_analysis_results;
    let mcafeeDetected = false;
    let mcafeeFound = false;
    let isMaliciousByOtherVendors = false;

    // Reseteamos la variable vendorInfo por cada hash
    vendorInfo += `<h4>Hash: ${hash}</h4>`;
    const vendorSet = new Set(); // Usamos un Set para eliminar duplicados en los vendors

    for (let vendor in analysisResults) {
      const result = analysisResults[vendor].result;
      const category = analysisResults[vendor].category;

      // Creamos una cadena única para cada vendor
      const vendorEntry = `Vendor: ${vendor}, Category: ${category}, Result: ${result || 'null'}`;

      // Agregamos la información del vendor al Set para evitar duplicados
      vendorSet.add(vendorEntry);

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

    // Convertimos el Set a un string sin duplicados y agregamos al popup
    vendorSet.forEach(vendorEntry => {
      if (vendorEntry.toLowerCase().includes('mcafee')) {
        vendorInfo += `<span class="mcafee-info">${vendorEntry}</span><br>`;
      } else {
        vendorInfo += `${vendorEntry}<br>`;
      }
    });

    // Si McAfee no lo encontró, verificamos si otro vendor lo detecta como malicioso
    if (!mcafeeFound || !mcafeeDetected) {
      if (isMaliciousByOtherVendors) {
        results.block.add(hash); // Se bloquea si otro vendor lo marca como malicioso y McAfee no lo detecta como tal
      } else {
        results.undetected.add(hash); // Si ningún vendor lo marca como malicioso, va a "Undetected by All Vendors"
      }
    } else {
      results.noBlock.add(hash); // Si McAfee lo detecta como malicioso, no se bloquea
    }

  } catch (error) {
    console.error(`Error procesando el hash ${hash}:`, error);
    results.invalid.add(hash); // Si ocurre un error, se considera inválido
  }
}


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
  if (vendorInfo) {
    document.getElementById('vendorInfo').innerHTML = vendorInfo;
    document.getElementById('vendorInfoPopup').style.display = 'block';
  } else {
    alert("No hay información de vendors disponible");
  }
}

// Función para cerrar el popup del ojo
function closeVendorInfoPopup() {
  document.getElementById('vendorInfoPopup').style.display = 'none';
}

// Asegurarse de que el botón del ojo funcione
document.getElementById('eyeButton').addEventListener('click', openVendorInfoPopup);

// Cerrar el popup si se hace clic fuera del popup
window.addEventListener('click', function(event) {
  const popup = document.getElementById('vendorInfoPopup');
  if (event.target === popup) {
    closeVendorInfoPopup();
  }
});

// Cerrar el popup con la tecla Esc
document.addEventListener('keydown', function(event) {
  if (event.key === 'Escape') {
    closeVendorInfoPopup();
  }
});

// Cerrar el popup con el botón de cerrar "X"
document.getElementById('closePopup').addEventListener('click', closeVendorInfoPopup);

// Función para limpiar los inputs
function clearInput() {
  document.getElementById('hashes').value = '';  // Limpiar el campo de texto
  clearResults();  // Limpiar las listas de resultados
}

// Asegúrate de que el botón "Clear" esté conectado correctamente
document.getElementById('clearButton').addEventListener('click', clearInput);
