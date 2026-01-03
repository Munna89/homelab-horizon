package server

const baseCSS = `
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; padding: 1rem; }
.container { max-width: 800px; margin: 0 auto; }
h1, h2 { margin-bottom: 1rem; color: #fff; font-size: 1.25rem; }
h1 { font-size: 1.5rem; }
.card { background: #16213e; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
input, button, select { font-size: 1rem; padding: 0.75rem 1rem; border-radius: 4px; border: none; line-height: 1; height: 2.75rem; box-sizing: border-box; vertical-align: middle; }
input, select { background: #0f3460; color: #fff; width: 100%; margin-bottom: 0.5rem; }
select { appearance: none; -webkit-appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23888' d='M6 8L1 3h10z'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 0.75rem center; padding-right: 2.5rem; cursor: pointer; }
input::placeholder { color: #888; }
button { background: #e94560; color: #fff; cursor: pointer; margin-right: 0.5rem; margin-bottom: 0.5rem; width: auto; display: inline-flex; align-items: center; justify-content: center; }
button:hover { background: #ff6b6b; }
button.secondary { background: #0f3460; }
button.secondary:hover { background: #1a4a7a; }
button.success { background: #2ecc71; }
button.success:hover { background: #27ae60; }
button.danger { background: #c0392b; }
button.danger:hover { background: #e74c3c; }
.error { background: #c0392b; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }
.success { background: #27ae60; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }
.info { background: #2980b9; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #0f3460; }
th { color: #888; font-weight: normal; font-size: 0.85rem; }
td { font-size: 0.9rem; }
pre { background: #0f3460; padding: 1rem; border-radius: 4px; overflow-x: auto; font-family: monospace; white-space: pre-wrap; word-break: break-all; font-size: 0.85rem; }
code { font-size: 0.85rem; word-break: break-all; }
.status-ok { color: #2ecc71; }
.status-err { color: #e74c3c; }
.flex { display: flex; gap: 0.5rem; flex-wrap: wrap; }
.mb-1 { margin-bottom: 1rem; }
a { color: #e94560; }
.modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; justify-content: center; align-items: center; }
.modal-overlay.active { display: flex; }
.modal-content { background: #16213e; padding: 1.5rem; border-radius: 8px; max-width: 95%; max-height: 90%; overflow: auto; position: relative; }
.modal-close { position: absolute; top: 0.5rem; right: 0.5rem; background: none; border: none; color: #888; font-size: 1.5rem; cursor: pointer; padding: 0.25rem 0.5rem; }
.modal-close:hover { color: #fff; background: none; }
.loading { display: inline-block; width: 1em; height: 1em; border: 2px solid #888; border-top-color: #fff; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5em; vertical-align: middle; }
@keyframes spin { to { transform: rotate(360deg); } }
/* Mobile responsive tables */
@media screen and (max-width: 640px) {
    body { padding: 0.5rem; }
    .card { padding: 0.75rem; }
    h1 { font-size: 1.25rem; }
    h2 { font-size: 1.1rem; }
    table, thead, tbody, th, td, tr { display: block; }
    thead tr { position: absolute; top: -9999px; left: -9999px; }
    tr { background: #0f3460; margin-bottom: 0.75rem; border-radius: 6px; padding: 0.5rem; }
    td { border: none; padding: 0.4rem 0.5rem; position: relative; padding-left: 40%; text-align: right; display: flex; justify-content: space-between; align-items: center; }
    td:before { content: attr(data-label); position: absolute; left: 0.5rem; width: 35%; text-align: left; font-weight: bold; color: #888; font-size: 0.8rem; }
    td:last-child { border-bottom: none; padding-top: 0.5rem; padding-left: 0.5rem; justify-content: flex-end; }
    td:last-child:before { display: none; }
    input, button, select { padding: 0.5rem 0.75rem; font-size: 0.85rem; height: 2.25rem; line-height: 1; }
    button { margin-right: 0.25rem; display: inline-flex; align-items: center; justify-content: center; }
    .modal-content { padding: 1rem; max-width: 98%; }
    details summary { font-size: 0.95rem; }
}
`
