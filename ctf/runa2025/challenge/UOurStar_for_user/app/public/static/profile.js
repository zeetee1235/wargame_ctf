document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('editForm');
  if (form) {
    const editBtn = document.getElementById('editBtn');
    const saveBtn = document.getElementById('saveBtn');
    const cancelBtn = document.getElementById('cancelBtn');

    const inputs = form.querySelectorAll(
      'textarea[name], input[name]:not([type="hidden"]):not([name="_csrf"])'
    );

    const enable = (yes) => {
      inputs.forEach(el => { el.disabled = !yes; });
      if (editBtn) editBtn.hidden =  yes;
      if (saveBtn) saveBtn.hidden = !yes;
      if (cancelBtn) cancelBtn.hidden = !yes;
    };

    if (editBtn) editBtn.addEventListener('click', () => enable(true));
    if (cancelBtn) cancelBtn.addEventListener('click', () => { form.reset(); enable(false); });

    enable(false);
  }

  const cfg  = window.cfg || document.getElementById('cfg');
  const allowList = ((cfg?.allow?.value) || cfg?.dataset?.allow || '')
    .split(',').map(s => s.trim()).filter(Boolean);

  function allowCss(raw) {
    try {
      return String(raw || '')
        .split(';')
        .map(x => x.trim())
        .filter(rule => allowList.length ? allowList.some(p => rule.startsWith(p)) : true)
        .join(';');
    } catch (_) { return ''; }
  }

  const card = document.getElementById('profile-card');
  if (card) {
    const themeRaw = card.getAttribute('data-theme') || '';
    card.setAttribute('style', allowCss(themeRaw));
  }
});
