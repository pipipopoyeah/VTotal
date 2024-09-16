document.getElementById('hashForm').addEventListener('submit', async function(event) {
  event.preventDefault();

  const hashes = document.getElementById('hashes').value;
  
  // Realiza la petición al servidor
  const response = await fetch('/check-hashes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ hashes: hashes })
  });

  const results = await response.json();

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
