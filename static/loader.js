/* Cargador de la página cifrada (2026-11-05, etapa 2, TR: «que nadie sin el enlace vea qué hace mi página»).
   La página publicada en GitHub Pages es PÚBLICA. Para que nadie sin el enlace vea qué hace, el código real va cifrado
   en app.enc / py.zip.enc y aquí se descifra con la clave que va tras el # del marcador (nunca viaja a ningún servidor).
   Sin clave, o con clave incorrecta, la página no arma nada. Lo genérico (Pyodide, html-to-image, fuentes) va en claro. */
(async () => {
  const marca = t => console.info('KB-LOADER: ' + t);
  const enc = s => new TextEncoder().encode(s);
  const candado = msg => {
    const d = document.getElementById('kb-candado');
    if (d) { d.textContent = msg; d.style.cssText = 'max-width:34rem;margin:4rem auto;padding:1.5rem;font:1rem/1.5 system-ui,sans-serif;color:#333;text-align:center'; }
  };
  const CLAVE = /^[A-Za-z0-9_-]{16,}$/;
  const clave = location.hash.slice(1);
  if (!CLAVE.test(clave)) { marca('bloqueado'); return candado('Abre esta página con tu enlace de acceso (el que termina en #clave) y guárdalo como marcador.'); }
  if (!(window.crypto && crypto.subtle)) return candado('Este navegador no permite abrir la página de forma segura (hace falta HTTPS).');
  let key;
  try {
    const hk = await crypto.subtle.importKey('raw', enc(clave), 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: enc('kb-pagina-salt-v1'), info: enc('kb-pagina-v1') }, hk, 256);
    key = await crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['decrypt']);
  } catch (e) { return candado('No se pudo preparar el descifrado de la página.'); }
  const descifrar = async (buf, aad) => new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12), additionalData: enc(aad) }, key, buf.slice(12)));
  window.__kbDescifrar = descifrar;  // api-web.js lo usa para py.zip.enc en modo local

  let meta;
  try {
    const buf = new Uint8Array(await (await fetch('app.enc', { cache: 'no-store' })).arrayBuffer());
    const frame = await descifrar(buf, 'app');  // falla si la clave no es la correcta (AES-GCM no verifica)
    const mlen = new DataView(frame.buffer, frame.byteOffset, 4).getUint32(0);
    meta = JSON.parse(new TextDecoder().decode(frame.slice(4, 4 + mlen)));
  } catch (e) { marca('clave-incorrecta'); return candado('Clave incorrecta: abre la página con el enlace que muestra KB Soporte en casa (termina en #clave).'); }

  document.body.innerHTML = meta.body;
  for (const css of meta.styles || []) { const s = document.createElement('style'); s.textContent = css; document.head.appendChild(s); }
  const cargarScript = sc => new Promise((res, rej) => {
    const s = document.createElement('script');  // clásico: conserva el orden y el alcance compartido entre scripts
    s.src = sc.src || URL.createObjectURL(new Blob([sc.code], { type: 'text/javascript' }));
    s.onload = res;
    s.onerror = () => rej(new Error('no cargó un script de la página'));
    document.body.appendChild(s);
  });
  try { for (const sc of meta.scripts || []) await cargarScript(sc); }  // uno a uno: mismo orden que las etiquetas originales
  catch (e) { return candado('No se pudo armar la página; vuelve a abrirla con tu enlace.'); }
  marca('listo');
})();
