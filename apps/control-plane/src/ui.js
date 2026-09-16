document.body.addEventListener('htmx:responseError', (event) => {
  const notice = document.getElementById('notice');
  if (!notice) return;
  notice.className = 'notice error';
  notice.textContent = event.detail.xhr.responseText || 'The request failed. Please retry.';
  notice.scrollIntoView({behavior: 'smooth', block: 'nearest'});
});
document.body.addEventListener('htmx:afterRequest', (event) => {
  if (!event.detail.successful) return;
  const element = event.detail.elt;
  const notice = document.getElementById('notice');
  if (event.detail.target === notice && notice) {
    notice.className = '';
    notice.scrollIntoView({behavior: 'smooth', block: 'nearest'});
  }
  const action = element.getAttribute('hx-post') || '';
  if (action.endsWith('/management') || action.endsWith('/plans')) window.location.reload();
  if (action.endsWith('/commands/pin')) element.reset();
});
