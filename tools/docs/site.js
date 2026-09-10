(() => {
  const indexURL = new URL(document.currentScript.dataset.index, location.href);
  const input = document.querySelector('#search');
  const status = document.querySelector('#search-status');
  const groups = [...document.querySelectorAll('nav details')];
  const rows = [...document.querySelectorAll('nav li')];
  let index;
  let searchVersion = 0;
  const mobile = matchMedia('(max-width: 720px)');
  const navigation = document.querySelector('#navigation');
  navigation.open = !mobile.matches;
  mobile.addEventListener('change', event => { navigation.open = !event.matches; });
  const load = () => index ||= fetch(indexURL).then(response => {
    if (!response.ok) throw new Error('Search unavailable');
    return response.json();
  }).then(pages => new Map(pages.map(page => [page.path, page.text])));
  input.addEventListener('input', async () => {
    const version = ++searchVersion;
    const terms = input.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
    if (!terms.length) {
      for (const row of rows) row.hidden = row.dataset.default !== 'true';
      for (const group of groups) {
        group.hidden = ![...group.querySelectorAll('li')].some(row => !row.hidden);
        group.open = group.dataset.open === 'true';
      }
      status.textContent = '';
      return;
    }
    try {
      const pages = await load();
      if (version !== searchVersion) return;
      let count = 0;
      for (const row of rows) {
        const text = `${row.textContent.toLowerCase()} ${pages.get(row.dataset.path) || ''}`;
        row.hidden = !terms.every(term => text.includes(term));
        if (!row.hidden) count++;
      }
      for (const group of groups) {
        group.hidden = ![...group.querySelectorAll('li')].some(row => !row.hidden);
        group.open = !group.hidden;
      }
      status.textContent = `${count} matching pages`;
    } catch {
      if (version !== searchVersion) return;
      status.textContent = 'Search is unavailable. Browse the sections below.';
    }
  });
})();
