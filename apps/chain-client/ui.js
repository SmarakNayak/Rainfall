const $ = selector => document.querySelector(selector);
const token = $('meta[name="rainfall-token"]').content;
let state;
const el = (tag, text) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; return node; };
async function request(path, body) {
  const response = await fetch(path, { method: body ? 'POST' : 'GET', headers: { 'x-rainfall-token': token, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
  const data = await response.json(); if (!response.ok) throw Error(data.error); return data;
}
async function action(body) {
  document.querySelectorAll('button').forEach(b => b.disabled = true);
  try {
    const result = await request('/action', body); state = result.state; render();
    $('#notice').textContent = body.action === 'sync' ? JSON.stringify(result.result) : 'Saved on this device.';
  } catch (error) { $('#notice').textContent = error.message; }
  finally { document.querySelectorAll('button').forEach(b => b.disabled = false); }
}
function render() {
  const own = state.accounts.find(a => a.id === state.account);
  $('#identity').replaceChildren(el('p', own ? own.name : 'No identity on this phone'), el('code', state.account ?? 'Create an identity or import history to recover one.'));
  $('#create').hidden = !!state.account;
  $('#peers textarea').value = state.peers.join('\n');
  $('#friend-options').replaceChildren(...state.accounts.filter(a => a.id !== state.account).map(a => { const o = el('option', `${a.name} · ${a.id.slice(0, 12)}`); o.value = a.id; return o; }));
  $('#accounts').replaceChildren(...state.accounts.map(account => {
    const article = el('article');
    article.append(el('h3', account.name), el('code', account.id), el('p', `${account.depth === null ? 'Imported / outside neighbourhood' : `${account.depth} friendship hops`} · ${account.status}`));
    article.append(el('small', `Locally selected continuation: ${account.head}`));
    const details = el('details'); details.append(el('summary', `${account.records.length} signed records · ${account.heads.length} branch tips`));
    const list = el('ol');
    for (const record of account.records) {
      const item = el('li'); item.append(el('strong', record.kind), el('p', new Date(record.time).toLocaleString()), el('code', record.id), el('p', `Parent: ${record.parent ?? 'origin'}`));
      if (record.kind === 'key-change') {
        item.append(el('p', `Claimed effective time: ${new Date(record.data.effectiveAt).toLocaleString()}`));
        for (const evidence of record.evidence) {
          const name = state.accounts.find(a => a.id === evidence.account)?.name ?? evidence.account;
          item.append(el('p', `${name}: ${evidence.supports ? 'endorses this replacement' : 'no endorsement of this replacement'}; signer history ${evidence.signerStatus}${evidence.targets.length > 1 ? '; endorses multiple candidates' : ''}`));
        }
        const attest = el('button', 'I verified my friend on this phone');
        attest.onclick = () => { if (confirm('Have you recognised this direct friend in person and verified this exact replacement key?')) action({ action: 'attest', target: record.id }); };
        item.append(attest);
      }
      const raw = el('details'); raw.append(el('summary', 'Signed record')); const { evidence, ...signed } = record; raw.append(el('pre', JSON.stringify(signed, null, 2))); item.append(raw);
      if (account.heads.includes(record.id)) {
        const choose = el('button', 'Follow this branch locally');
        choose.onclick = () => { if (confirm('Use this branch for this identity on your device? Other observers decide independently.')) action({ action: 'select', account: account.id, head: record.id }); };
        item.append(choose);
      }
      list.append(item);
    }
    details.append(list); article.append(details); return article;
  }));
}
$('#create').onsubmit = event => { event.preventDefault(); action({ action: 'create', name: new FormData(event.target).get('name') }); };
$('#friend').onsubmit = event => { event.preventDefault(); action({ action: 'friend', peer: new FormData(event.target).get('peer') }); };
$('#peers').onsubmit = event => { event.preventDefault(); action({ action: 'peers', peers: new FormData(event.target).get('peers').split('\n').map(s => s.trim()).filter(Boolean) }); };
$('#recover').onsubmit = event => { event.preventDefault(); const form = new FormData(event.target); if (confirm('Generate a fresh controlling key for this candidate branch?')) action({ action: 'recover', parent: form.get('parent'), effectiveAt: new Date(form.get('time')).getTime() }); };
$('#sync').onclick = () => action({ action: 'sync' });
$('#import').onchange = async event => {
  try { const file = event.target.files[0]; if (!file) return; if (file.size > 8 * 1024 * 1024) throw Error('Bundle too large'); await action({ action: 'import', records: JSON.parse(await file.text()) }); }
  catch (error) { $('#notice').textContent = error.message; }
  event.target.value = '';
};
$('#export').onclick = () => {
  const records = state.accounts.flatMap(a => a.records.map(({ evidence, ...r }) => r));
  const url = URL.createObjectURL(new Blob([JSON.stringify(records, null, 2)], { type: 'application/json' }));
  const link = el('a'); link.href = url; link.download = 'rainfall-histories.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
};
try { state = await request('/state'); render(); } catch (error) { $('#notice').textContent = error.message; }
