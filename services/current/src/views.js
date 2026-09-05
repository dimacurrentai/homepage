export function escape(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
}

export function form(action, csrf, body) {
  return `<form method="post" action="${escape(action)}"><input type="hidden" name="csrf" value="${escape(csrf)}">${body}</form>`;
}

export function page(title, body, origin = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · Current</title><link rel="stylesheet" href="${escape(origin)}/assets/style.css"></head><body><header><a class="wordmark" href="${escape(origin)}/">current<span>↗</span></a><nav><a href="${escape(origin)}/#demos">Demos</a><a href="${escape(origin)}/setup">Build with Current</a></nav></header><main class="document">${body}</main><footer><span>Current · Working experiments</span><a href="https://github.com/c5t/current">Current on GitHub ↗</a></footer></body></html>`;
}
