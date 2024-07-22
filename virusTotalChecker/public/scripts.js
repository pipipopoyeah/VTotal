function clearInput() {
  document.getElementById('hashes').value = '';
  document.getElementById('blockList').innerHTML = '';
  document.getElementById('noBlockList').innerHTML = '';
  document.getElementById('invalidList').innerHTML = '';
  document.getElementById('undetectedList').innerHTML = '';
}

function copyToClipboard(listId) {
  const list = document.getElementById(listId);
  const text = Array.from(list.children).map(li => li.textContent).join('\n');
  navigator.clipboard.writeText(text).catch(err => {
    console.error('Could not copy text: ', err);
  });
}
