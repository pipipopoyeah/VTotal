// Inserta tu API key aquí
const VIRUSTOTAL_API_KEY = '85cf97a6b2db72efc28aa90d39a79e24740bbcc231e99ce46ed41f79b0140490';
let vendorInfo = ''; // Variable para almacenar la información de los vendors

document.getElementById('hashForm').addEventListener('submit', async function(event) {
  event.preventDefault();

  const hashes = document.getElementById('hashes').value.split('\n').map(hash => hash.trim()).filter(hash => hash);
  const results = { block: [], noBlock: [], invalid: [], undetected: [] };
  vendorInfo = ''; // Reinicia la información de los vendors

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
        throw new Error(`Error en la solicitud a VirusTotal: ${response.status}`);
      }

      const data = await response.json();
      const analysisResults = data.data.attributes.last_analysis_results;
      let mcafeeDetected = false;
      let mcafeeFound = false;
      let isMaliciousByOtherVendors = false;

      // Reseteamos la variable vendorInfo por cada hash
      vendorInfo += `<h4>Hash: ${hash}</h4>`;

      for (let vendor in analysisResults) {
        const result = analysisResults[vendor].result;
        const category = analysisResults[vendor].category;

        // Guarda la información de los vendors para mostrar en el popup
        if (vendor.toLowerCase().includes('mcafee')) {
          vendorInfo += `<span class="mcafee-info">Vendor: ${vendor}, Category: ${category}, Result: ${result || 'null'}</span><br>`;
        } else {
          vendorInfo += `Vendor: ${vendor}, Category: ${category}, Result: ${result || 'null'}<br>`;
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

      // Si McAfee no lo encontró, verificamos si otro vendor lo detecta como malicioso
      if (!mcafeeFound || !mcafeeDetected) {
        if (isMaliciousByOtherVendors) {
          results.block.push(hash); // Se bloquea si otro vendor lo marca como malicioso y McAfee no lo detecta como tal
        } else {
          results.undetected.push(hash); // Si ningún vendor lo marca como malicioso, va a "Undetected by All Vendors"
        }
      } else {
        results.noBlock.push(hash); // Si McAfee lo detecta como malicioso, no se bloquea
      }

    } catch (error) {
      results.invalid.push(hash); // Si ocurre un error, se considera inválido
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

function clearInput() {
  document.getElementById('hashes').value = '';  // Limpiar el campo de texto
  clearResults();  // Limpiar las listas de resultados
}

// Asegúrate de que el botón "Clear" esté conectado correctamente
document.getElementById('clearButton').addEventListener('click', clearInput);