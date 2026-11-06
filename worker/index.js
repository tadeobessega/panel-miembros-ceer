/* Panel de miembros del CEER (Cloudflare Worker + D1).
   Todo se arma en el servidor: sin sesión válida no sale ningún enlace.
   Rutas: /login, /salir, / (accesos), /perfil (GitHub), /clave (cambiar clave), /admin (miembros y accesos),
   /intercambio-comercial-provincial (página servida desde public/, solo con sesión). */

import { usuarioGitHub, darAcceso, quitarAcceso, estadoBackups, DUENO } from './github.js';

const SESION_DIAS = 30;
const ITER = 100000;
const MAX_FALLOS = 5;
const BLOQUEO_MIN = 15;
const COOKIE = '__Host-ceer_panel';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === 'POST' && !mismoOrigen(request, url)) return texto('Origen no permitido', 403);
      const pag = PAGINAS.find((x) => url.pathname === x || url.pathname.startsWith(x + '/'));
      if (pag) return await paginaInterna(request, env, url, pag);
      const r = RUTAS[url.pathname];
      if (!r) return redirigir('/');
      return await r(request, env, url);
    } catch (e) {
      console.error(e);
      return pagina({ titulo: 'Error', cuerpo: aviso('Algo salió mal', 'Probá de nuevo en un rato.') }, 500);
    }
  },

  /* Cada hora: revisa el acceso a GitHub del miembro que hace más tiempo que no se revisa
     (uno por corrida, para no pasar el límite de pedidos de Cloudflare). Así los repos nuevos
     también les llegan a todos. */
  async scheduled(event, env, ctx) {
    if (!env.GITHUB_TOKEN) return;
    const m = await env.DB.prepare(
      "SELECT usuario, github, activo FROM usuarios WHERE github IS NOT NULL AND github != '' ORDER BY github_revisado LIMIT 1"
    ).first();
    if (!m) return;
    let estado;
    try {
      if (m.activo) estado = await darAcceso(env, m.github);
      else { await quitarAcceso(env, m.github); estado = 'Sin acceso (cuenta desactivada)'; }
    } catch (e) { estado = 'Error al revisar: ' + e.message; }
    await env.DB.prepare('UPDATE usuarios SET github_estado = ?, github_revisado = ? WHERE usuario = ?')
      .bind(estado, Date.now(), m.usuario).run();
  }
};

/* Páginas del CEER que se publican dentro del panel (archivos en public/<ruta>/index.html). */
const PAGINAS = ['/intercambio-comercial-provincial'];

async function paginaInterna(request, env, url, pag) {
  const { respuesta } = await exigir(request, env);
  if (respuesta) return respuesta;
  if (url.pathname === pag) return redirigir(pag + '/');
  const r = await env.ASSETS.fetch(new Request(new URL(url.pathname, url.origin), request));
  const h = new Headers(r.headers);
  h.set('cache-control', 'private, no-store');
  h.set('x-robots-tag', 'noindex');
  return new Response(r.body, { status: r.status, headers: h });
}

const RUTAS = {
  '/': panel,
  '/login': login,
  '/salir': salir,
  '/clave': clave,
  '/perfil': perfil,
  '/admin': admin,
  '/favicon.ico': async () => new Response(null, { status: 204 })
};

/* ---------------- sesión ---------------- */
async function sesion(request, env) {
  const token = leerCookie(request, COOKIE);
  if (!token) return null;
  const u = await env.DB.prepare(
    `SELECT u.* FROM sesiones s JOIN usuarios u ON u.usuario = s.usuario
     WHERE s.token_hash = ? AND s.vence > ? AND u.activo = 1`
  ).bind(await sha256(token), Date.now()).first();
  return u || null;
}

async function exigir(request, env, { admin = false, permitirCambio = false } = {}) {
  const u = await sesion(request, env);
  if (!u) return { respuesta: redirigir('/login') };
  if (u.debe_cambiar && !permitirCambio) return { respuesta: redirigir('/clave') };
  if (admin && u.rol !== 'admin') return { respuesta: redirigir('/') };
  return { u };
}

/* ---------------- rutas ---------------- */
async function login(request, env) {
  if (request.method === 'GET') {
    if (await sesion(request, env)) return redirigir('/');
    return pagina({ titulo: 'Ingresar', cuerpo: formLogin() });
  }
  const f = await request.formData();
  const usuario = String(f.get('usuario') || '').trim().toLowerCase();
  const claveIng = String(f.get('clave') || '');
  const u = await env.DB.prepare('SELECT * FROM usuarios WHERE usuario = ?').bind(usuario).first();
  const ahora = Date.now();
  if (u && u.bloqueo_hasta > ahora) {
    return pagina({ titulo: 'Ingresar', cuerpo: formLogin(usuario, `Demasiados intentos. Probá de nuevo en ${BLOQUEO_MIN} minutos.`) }, 429);
  }
  const okClave = u && u.activo && safeEqual(await pbkdf2(claveIng, u.sal), u.hash);
  if (!okClave) {
    if (u) {
      const fallos = u.fallos + 1;
      await env.DB.prepare('UPDATE usuarios SET fallos = ?, bloqueo_hasta = ? WHERE usuario = ?')
        .bind(fallos >= MAX_FALLOS ? 0 : fallos, fallos >= MAX_FALLOS ? ahora + BLOQUEO_MIN * 60000 : 0, usuario).run();
    }
    return pagina({ titulo: 'Ingresar', cuerpo: formLogin(usuario, 'Usuario o contraseña incorrectos.') }, 401);
  }
  const token = hexAleatorio(32);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sesiones WHERE vence < ?').bind(ahora),
    env.DB.prepare('INSERT INTO sesiones (token_hash, usuario, vence) VALUES (?, ?, ?)')
      .bind(await sha256(token), u.usuario, ahora + SESION_DIAS * 864e5),
    env.DB.prepare('UPDATE usuarios SET fallos = 0, bloqueo_hasta = 0 WHERE usuario = ?').bind(u.usuario)
  ]);
  return redirigir(u.debe_cambiar ? '/clave' : '/', {
    'set-cookie': `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESION_DIAS * 86400}`
  });
}

async function salir(request, env) {
  const token = leerCookie(request, COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sesiones WHERE token_hash = ?').bind(await sha256(token)).run();
  return redirigir('/login', { 'set-cookie': `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });
}

async function panel(request, env) {
  const { u, respuesta } = await exigir(request, env);
  if (respuesta) return respuesta;
  const { results } = await env.DB.prepare('SELECT * FROM accesos ORDER BY orden, id').all();
  const secciones = [];
  for (const a of results) {
    let s = secciones.find((x) => x.nombre === a.seccion);
    if (!s) secciones.push((s = { nombre: a.seccion, accesos: [] }));
    s.accesos.push(a);
  }
  const cuerpo = `
    <h1>Panel de miembros del CEER</h1>
    <p class="bajada">Accesos a los sitios, tableros, herramientas y archivos del centro.</p>
    ${secciones.length ? secciones.map((s) => `
      <section><h2>${esc(s.nombre)}</h2><div class="accesos">${s.accesos.map(tarjetaAcceso).join('')}</div></section>`).join('')
      : aviso('Todavía no hay accesos', u.rol === 'admin' ? 'Cargalos desde Administración.' : 'Pronto van a aparecer acá.')}`;
  return pagina({ titulo: 'Accesos', u, activa: '/', cuerpo });
}

async function clave(request, env) {
  const { u, respuesta } = await exigir(request, env, { permitirCambio: true });
  if (respuesta) return respuesta;
  if (request.method === 'GET') return pagina({ titulo: 'Cambiar contraseña', u, activa: '/clave', cuerpo: formClave(u) });
  const f = await request.formData();
  const actual = String(f.get('actual') || '');
  const nueva = String(f.get('nueva') || '');
  const repetir = String(f.get('repetir') || '');
  let error = '';
  if (!safeEqual(await pbkdf2(actual, u.sal), u.hash)) error = 'La contraseña actual no es correcta.';
  else if (nueva.length < 10) error = 'La nueva contraseña tiene que tener al menos 10 caracteres.';
  else if (nueva !== repetir) error = 'Las dos contraseñas nuevas no coinciden.';
  else if (nueva === actual) error = 'La nueva contraseña tiene que ser distinta de la actual.';
  if (error) return pagina({ titulo: 'Cambiar contraseña', u, activa: '/clave', cuerpo: formClave(u, error) }, 400);
  const sal = hexAleatorio(16);
  const token = leerCookie(request, COOKIE);
  await env.DB.batch([
    env.DB.prepare('UPDATE usuarios SET hash = ?, sal = ?, debe_cambiar = 0 WHERE usuario = ?')
      .bind(await pbkdf2(nueva, sal), sal, u.usuario),
    // cierra las otras sesiones de ese usuario
    env.DB.prepare('DELETE FROM sesiones WHERE usuario = ? AND token_hash != ?').bind(u.usuario, await sha256(token))
  ]);
  return redirigir('/?ok=clave');
}

async function perfil(request, env) {
  const { u, respuesta } = await exigir(request, env);
  if (respuesta) return respuesta;
  let msj = '';
  if (request.method === 'POST') {
    const f = await request.formData();
    const pedido = String(f.get('github') || '').trim().replace(/^@/, '').replace(/^https?:\/\/github\.com\//i, '').replace(/\/.*$/, '');
    if (!pedido) {
      if (u.github) await quitarAcceso(env, u.github);
      await env.DB.prepare('UPDATE usuarios SET github = NULL, github_estado = NULL WHERE usuario = ?').bind(u.usuario).run();
      u.github = null; u.github_estado = null;
      msj = ok('Sacaste tu usuario de GitHub del panel.');
    } else {
      let login = null, falla = '';
      try { login = await usuarioGitHub(env, pedido); } catch (e) { falla = e.message; }
      if (falla) {
        msj = error(falla);
      } else if (!login) {
        msj = error(`No encontramos el usuario de GitHub "${pedido}".`);
      } else {
        const ocupado = await env.DB.prepare('SELECT nombre FROM usuarios WHERE lower(github) = lower(?) AND usuario != ?').bind(login, u.usuario).first();
        if (ocupado) msj = error(`Ese usuario de GitHub ya está cargado por ${ocupado.nombre}.`);
        else {
          if (u.github && u.github.toLowerCase() !== login.toLowerCase()) await quitarAcceso(env, u.github);
          let estado;
          try { estado = await darAcceso(env, login); } catch (e) { estado = 'Error: ' + e.message; }
          await env.DB.prepare('UPDATE usuarios SET github = ?, github_estado = ?, github_revisado = ? WHERE usuario = ?')
            .bind(login, estado, Date.now(), u.usuario).run();
          u.github = login; u.github_estado = estado;
          msj = ok('Guardado.');
        }
      }
    }
  }
  const cuerpo = `
    <h1>Tu perfil</h1>
    <p class="bajada">${esc(u.nombre)} · usuario <span class="mono">${esc(u.usuario)}</span></p>
    ${msj}
    <section><h2>GitHub</h2>
      <div class="caja">
        <p class="texto">Cargá tu usuario de GitHub y te damos permiso de edición en todos los repos del CEER. GitHub te manda una invitación por mail para cada repo: hasta que la aceptes no vas a poder editar.</p>
        <form method="post" action="/perfil" class="form fila">
          <label>Usuario de GitHub<input name="github" value="${esc(u.github || '')}" placeholder="tu-usuario" autocapitalize="none" spellcheck="false"></label>
          <div class="botones"><button class="boton" type="submit">Guardar</button></div>
        </form>
        ${u.github ? `<p class="estado-gh"><a href="https://github.com/${esc(u.github)}" target="_blank" rel="noopener" class="mono">github.com/${esc(u.github)}</a> · ${esc(u.github_estado || 'sin revisar')}</p>
          <p class="estado-gh"><a href="https://github.com/notifications" target="_blank" rel="noopener">Ver invitaciones pendientes en GitHub ↗</a></p>` : ''}
      </div>
    </section>
    <section><h2>Contraseña</h2>
      <div class="caja"><p class="texto">Al cambiarla se cierran tus otras sesiones abiertas.</p><a class="boton" href="/clave">Cambiar contraseña</a></div>
    </section>`;
  return pagina({ titulo: 'Perfil', u, activa: '/perfil', cuerpo });
}

async function admin(request, env, url) {
  const { u, respuesta } = await exigir(request, env, { admin: true });
  if (respuesta) return respuesta;
  let mensaje = '';
  if (request.method === 'POST') {
    const f = await request.formData();
    const accion = String(f.get('accion') || '');
    const usuario = String(f.get('usuario') || '').trim().toLowerCase();
    const db = env.DB;
    switch (accion) {
      case 'crear': {
        const nombre = String(f.get('nombre') || '').trim();
        const rol = f.get('rol') === 'admin' ? 'admin' : 'miembro';
        if (!/^[a-z0-9._-]{3,30}$/.test(usuario) || !nombre) { mensaje = error('Completá el nombre y un usuario de 3 a 30 letras minúsculas, números, punto o guion.'); break; }
        if (await db.prepare('SELECT 1 FROM usuarios WHERE usuario = ?').bind(usuario).first()) { mensaje = error('Ese usuario ya existe.'); break; }
        const temp = claveTemporal();
        const sal = hexAleatorio(16);
        await db.prepare('INSERT INTO usuarios (usuario, nombre, rol, hash, sal, debe_cambiar) VALUES (?, ?, ?, ?, ?, 1)')
          .bind(usuario, nombre, rol, await pbkdf2(temp, sal), sal).run();
        mensaje = claveMostrada(nombre, usuario, temp, 'creado');
        break;
      }
      case 'restablecer': {
        const m = await db.prepare('SELECT * FROM usuarios WHERE usuario = ?').bind(usuario).first();
        if (!m) break;
        const temp = claveTemporal();
        const sal = hexAleatorio(16);
        await db.batch([
          db.prepare('UPDATE usuarios SET hash = ?, sal = ?, debe_cambiar = 1, fallos = 0, bloqueo_hasta = 0 WHERE usuario = ?')
            .bind(await pbkdf2(temp, sal), sal, usuario),
          db.prepare('DELETE FROM sesiones WHERE usuario = ?').bind(usuario)
        ]);
        mensaje = claveMostrada(m.nombre, usuario, temp, 'restablecido');
        break;
      }
      case 'github': {
        const m = await db.prepare('SELECT * FROM usuarios WHERE usuario = ?').bind(usuario).first();
        if (!m || !m.github) break;
        let estado;
        try { estado = m.activo ? await darAcceso(env, m.github) : 'Sin acceso (cuenta desactivada)'; } catch (e) { estado = 'Error: ' + e.message; }
        await db.prepare('UPDATE usuarios SET github_estado = ?, github_revisado = ? WHERE usuario = ?').bind(estado, Date.now(), usuario).run();
        mensaje = ok(`GitHub de ${m.nombre}: ${estado}`);
        break;
      }
      case 'activar':
      case 'desactivar': {
        if (usuario === u.usuario) { mensaje = error('No podés desactivar tu propia cuenta.'); break; }
        const m = await db.prepare('SELECT github FROM usuarios WHERE usuario = ?').bind(usuario).first();
        if (m && m.github) {
          try { if (accion === 'desactivar') await quitarAcceso(env, m.github); else await darAcceso(env, m.github); } catch {}
        }
        await db.batch([
          db.prepare('UPDATE usuarios SET activo = ? WHERE usuario = ?').bind(accion === 'activar' ? 1 : 0, usuario),
          db.prepare('DELETE FROM sesiones WHERE usuario = ?').bind(usuario)
        ]);
        mensaje = ok(accion === 'activar' ? 'Cuenta activada.' : 'Cuenta desactivada y sin acceso a los repos.');
        break;
      }
      case 'eliminar': {
        if (usuario === u.usuario) { mensaje = error('No podés eliminar tu propia cuenta.'); break; }
        const m = await db.prepare('SELECT github FROM usuarios WHERE usuario = ?').bind(usuario).first();
        if (m && m.github) { try { await quitarAcceso(env, m.github); } catch {} }
        await db.batch([
          db.prepare('DELETE FROM sesiones WHERE usuario = ?').bind(usuario),
          db.prepare('DELETE FROM usuarios WHERE usuario = ?').bind(usuario)
        ]);
        mensaje = ok('Cuenta eliminada.');
        break;
      }
      case 'acceso-guardar': {
        const d = {
          seccion: String(f.get('seccion') || '').trim(),
          titulo: String(f.get('titulo') || '').trim(),
          descripcion: String(f.get('descripcion') || '').trim(),
          url: String(f.get('url') || '').trim(),
          tipo: String(f.get('tipo') || '').trim(),
          repo: String(f.get('repo') || '').trim().replace(/^https?:\/\/github\.com\//i, '').replace(/\/$/, ''),
          estado: f.get('estado') === 'pendiente' ? 'pendiente' : 'activo',
          orden: parseInt(f.get('orden'), 10) || 0
        };
        if (!d.seccion || !d.titulo || !/^(https?:\/\/|\/)/.test(d.url)) { mensaje = error('Completá sección, título y un enlace que empiece con https://.'); break; }
        if (d.repo && !/^[\w.-]+\/[\w.-]+$/.test(d.repo)) { mensaje = error('El repo va como dueño/nombre, por ejemplo tadeobessega/ipceer.'); break; }
        const id = parseInt(f.get('id'), 10);
        if (id) {
          await db.prepare('UPDATE accesos SET seccion=?, titulo=?, descripcion=?, url=?, tipo=?, repo=?, estado=?, orden=? WHERE id=?')
            .bind(d.seccion, d.titulo, d.descripcion, d.url, d.tipo, d.repo || null, d.estado, d.orden, id).run();
          mensaje = ok('Acceso guardado.');
        } else {
          await db.prepare('INSERT INTO accesos (seccion, titulo, descripcion, url, tipo, repo, estado, orden) VALUES (?,?,?,?,?,?,?,?)')
            .bind(d.seccion, d.titulo, d.descripcion, d.url, d.tipo, d.repo || null, d.estado, d.orden).run();
          mensaje = ok('Acceso agregado.');
        }
        break;
      }
      case 'acceso-eliminar':
        await db.prepare('DELETE FROM accesos WHERE id = ?').bind(parseInt(f.get('id'), 10) || 0).run();
        mensaje = ok('Acceso eliminado.');
        break;
    }
  }
  const { results: miembros } = await env.DB.prepare('SELECT * FROM usuarios ORDER BY rol = \'admin\' DESC, nombre').all();
  const { results: accesos } = await env.DB.prepare('SELECT * FROM accesos ORDER BY orden, id').all();
  const backups = await estadoBackups();
  return pagina({ titulo: 'Administración', u, activa: '/admin', cuerpo: vistaAdmin(u, miembros, accesos, mensaje, backups, !!env.GITHUB_TOKEN) });
}

/* ---------------- vistas ---------------- */
function tarjetaAcceso(a) {
  const externo = /^https?:/.test(a.url);
  const pend = a.estado === 'pendiente';
  const repo = a.repo ? `<a class="repo" href="https://github.com/${esc(a.repo)}" target="_blank" rel="noopener" title="Repo en GitHub: ${esc(a.repo)}">repo <span aria-hidden="true">↗</span></a>` : '';
  return `<div class="acceso${pend ? ' pendiente' : ''}">
    <div class="tipo"><span>${esc(a.tipo)}</span>${pend ? '<span class="etiqueta">Pendiente</span>' : ''}</div>
    <h3><a class="principal" href="${esc(a.url)}"${externo ? ' target="_blank" rel="noopener"' : ''}>${esc(a.titulo)}</a></h3>
    <p>${esc(a.descripcion)}</p>
    <div class="pie-acceso"><span class="destino">${esc(host(a.url))}</span>${repo}</div></div>`;
}

function formLogin(usuario = '', err = '') {
  return `<div class="caja angosta">
    <h1 class="chico espacio">Iniciar sesión</h1>
    ${err ? `<p class="msj error">${esc(err)}</p>` : ''}
    <form method="post" action="/login" class="form">
      <label>Usuario<input name="usuario" autocomplete="username" autocapitalize="none" required value="${esc(usuario)}"></label>
      <label>Contraseña<input name="clave" type="password" autocomplete="current-password" required></label>
      <button class="boton" type="submit">Ingresar</button>
    </form></div>`;
}

function formClave(u, err = '') {
  return `<div class="caja angosta">
    <h1 class="chico">Cambiar contraseña</h1>
    <p class="bajada">${u.debe_cambiar ? 'Es tu primer ingreso o te restablecieron la clave: elegí una contraseña propia para seguir.' : 'Al cambiarla se cierran tus otras sesiones abiertas.'}</p>
    ${err ? `<p class="msj error">${esc(err)}</p>` : ''}
    <form method="post" action="/clave" class="form">
      <input type="hidden" name="usuario" value="${esc(u.usuario)}" autocomplete="username">
      <label>Contraseña actual<input name="actual" type="password" autocomplete="current-password" required></label>
      <label>Contraseña nueva <span class="ayuda">(10 caracteres o más)</span><input name="nueva" type="password" minlength="10" autocomplete="new-password" required></label>
      <label>Repetí la contraseña nueva<input name="repetir" type="password" minlength="10" autocomplete="new-password" required></label>
      <button class="boton" type="submit">Guardar</button>
    </form></div>`;
}

function vistaAdmin(u, miembros, accesos, mensaje, backups, conToken) {
  const filas = miembros.map((m) => {
    const yo = m.usuario === u.usuario;
    const estado = !m.activo ? 'Desactivada' : m.debe_cambiar ? 'Falta cambiar la clave' : 'Activa';
    const btn = (accion, txt, conf) => `<form method="post" action="/admin"${conf ? ` onsubmit="return confirm('${conf}')"` : ''}>
      <input type="hidden" name="accion" value="${accion}"><input type="hidden" name="usuario" value="${esc(m.usuario)}">
      <button class="link" type="submit">${txt}</button></form>`;
    return `<tr${m.activo ? '' : ' class="inactiva"'}>
      <td><strong>${esc(m.nombre)}</strong></td><td class="mono">${esc(m.usuario)}</td>
      <td>${m.rol === 'admin' ? 'Administrador' : 'Miembro'}</td><td>${estado}</td>
      <td>${m.github ? `<a class="mono" href="https://github.com/${esc(m.github)}" target="_blank" rel="noopener">${esc(m.github)}</a><div class="estado-gh">${esc(m.github_estado || 'sin revisar')}</div>` : '<span class="estado-gh">sin cargar</span>'}</td>
      <td><div class="acciones">${m.github ? btn('github', 'Revisar GitHub') : ''}${btn('restablecer', 'Restablecer clave', `¿Generar una clave nueva para ${esc(m.nombre)}?`)}
        ${yo ? '' : btn(m.activo ? 'desactivar' : 'activar', m.activo ? 'Desactivar' : 'Activar')}
        ${yo ? '' : btn('eliminar', 'Eliminar', `¿Eliminar la cuenta de ${esc(m.nombre)}?`)}</div></td></tr>`;
  }).join('');

  const formAcceso = (a = {}) => `<form method="post" action="/admin" class="form acceso-form">
      <input type="hidden" name="accion" value="acceso-guardar"><input type="hidden" name="id" value="${a.id || ''}">
      <label>Sección<input name="seccion" required value="${esc(a.seccion || '')}" list="secciones"></label>
      <label>Título<input name="titulo" required value="${esc(a.titulo || '')}"></label>
      <label>Tipo<input name="tipo" value="${esc(a.tipo || '')}" placeholder="Tablero, Drive…"></label>
      <label>Repo<input name="repo" value="${esc(a.repo || '')}" placeholder="tadeobessega/nombre"></label>
      <label class="ancho">Descripción<input name="descripcion" value="${esc(a.descripcion || '')}"></label>
      <label class="ancho">Enlace<input name="url" required value="${esc(a.url || '')}" placeholder="https://"></label>
      <label>Estado<select name="estado"><option value="activo">Activo</option><option value="pendiente"${a.estado === 'pendiente' ? ' selected' : ''}>Pendiente</option></select></label>
      <label>Orden<input name="orden" type="number" value="${a.orden ?? (accesos.length + 1) * 10}"></label>
      <div class="botones"><button class="boton" type="submit">${a.id ? 'Guardar' : 'Agregar acceso'}</button></div>
    </form>
    ${a.id ? `<form method="post" action="/admin" class="eliminar-acceso" onsubmit="return confirm('¿Eliminar este acceso?')">
      <input type="hidden" name="accion" value="acceso-eliminar"><input type="hidden" name="id" value="${a.id}">
      <button class="link" type="submit">Eliminar</button></form>` : ''}`;

  const secciones = [...new Set(accesos.map((a) => a.seccion))];
  return `
    <h1>Administración del panel</h1>
    <p class="bajada">Cuentas de los miembros y enlaces del panel. Las claves nuevas se muestran una sola vez: pasáselas a cada miembro por un canal privado.</p>
    ${mensaje}
    <section><h2>Miembros</h2>
      <div class="tabla"><table><thead><tr><th>Nombre</th><th>Usuario</th><th>Rol</th><th>Estado</th><th>GitHub</th><th></th></tr></thead><tbody>${filas}</tbody></table></div>
      <h3 class="sub">Agregar miembro</h3>
      <form method="post" action="/admin" class="form fila">
        <input type="hidden" name="accion" value="crear">
        <label>Nombre y apellido<input name="nombre" required></label>
        <label>Usuario<input name="usuario" required pattern="[a-z0-9._\\-]{3,30}" autocapitalize="none" placeholder="nombre"></label>
        <label>Rol<select name="rol"><option value="miembro">Miembro</option><option value="admin">Administrador</option></select></label>
        <div class="botones"><button class="boton" type="submit">Crear cuenta</button></div>
      </form>
    </section>
    ${conToken ? '' : `<p class="msj error">Para dar acceso a los repos falta el token de GitHub: en Cloudflare, Worker panel-miembros-ceer, Settings, Variables and Secrets, agregá un secreto <span class="mono">GITHUB_TOKEN</span> con un token de ${DUENO} que pueda administrar colaboradores (classic con permiso repo, o fine-grained con Administration: read and write en todos los repos).</p>`}
    <section><h2>Backups de los repos</h2>${vistaBackups(backups)}</section>
    <section><h2>Accesos</h2>
      <datalist id="secciones">${secciones.map((s) => `<option value="${esc(s)}">`).join('')}</datalist>
      ${accesos.map((a) => `<div class="caja editor">${formAcceso(a)}</div>`).join('')}
      <h3 class="sub">Agregar acceso</h3>
      <div class="caja editor">${formAcceso()}</div>
    </section>`;
}

function vistaBackups(b) {
  if (!b || !b.repos) return `<div class="caja"><p class="texto sin">Todavía no hay backups. Los hace la PC todos los días después de la tarea del IPCEER (scripts/backup_repos.ps1) y los guarda en OneDrive.</p></div>`;
  const filas = b.repos.map((r) => `<tr><td class="mono">${esc(r.repo)}</td><td>${esc(r.ultimo_backup ? r.ultimo_backup.split('-').reverse().join('/') : '')}</td>
    <td class="num mono">${esc(String(r.copias))}</td><td class="num mono">${esc(String(r.mb).replace('.', ','))}</td><td>${esc(r.estado)}</td></tr>`).join('');
  const f = String(b.corrida || '');
  return `<p class="texto">Última corrida: <span class="mono">${esc(f.slice(8, 10) + '/' + f.slice(5, 7) + '/' + f.slice(0, 4) + ' ' + f.slice(11, 16))}</span> en la PC ${esc(b.pc || '')}. Carpeta: <span class="mono">${esc(b.carpeta || '')}</span>. Se guarda un .bundle con toda la historia cuando el repo cambia; quedan los últimos 30 días y el primero de cada mes. Para restaurar: <span class="mono">git clone archivo.bundle carpeta</span>.</p>
    <div class="tabla"><table><thead><tr><th>Repo</th><th>Último backup</th><th class="num">Copias</th><th class="num">MB</th><th>Estado</th></tr></thead><tbody>${filas}</tbody></table></div>`;
}

const ok = (t) => `<p class="msj ok">${esc(t)}</p>`;
const error = (t) => `<p class="msj error">${esc(t)}</p>`;
const claveMostrada = (nombre, usuario, temp, verbo) => `<div class="msj clave">
  <p>Usuario ${verbo} para <strong>${esc(nombre)}</strong>. Pasale estos datos; al entrar va a tener que elegir su propia contraseña.</p>
  <p class="mono">Usuario: ${esc(usuario)}<br>Clave temporal: ${esc(temp)}</p></div>`;
const aviso = (t, txt) => `<div class="caja"><h2>${esc(t)}</h2><p class="bajada sin">${esc(txt)}</p></div>`;

/* ---------------- plantilla ---------------- */
const LOGO = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 469 110" width="100%" height="100%" aria-hidden="true"><path fill="currentColor" d="M60.5 110Q31.6 110 15.8 95.8Q0 81.5 0 54.8Q0 28.8 14.4 14.4Q28.8 0 55.5 0Q71.9 0 83.7 6.4Q95.4 12.8 100.3 24.5L80.7 40.1Q76.3 33.2 69.5 29.4Q62.8 25.7 54.7 25.7Q42 25.7 34.9 33Q27.7 40.3 27.7 53.8Q27.7 68.7 36.9 76.5Q46 84.3 62.9 84.3Q70.1 84.3 77.2 83.6Q84.4 82.9 91.2 81.7L94 107Q85.9 108.8 77.3 109.4Q68.7 110 60.5 110ZM156.5 110Q129 110 114 95.8Q99 81.5 99 54.8Q99 28.8 111.8 14.4Q124.5 0 147.7 0Q170.4 0 182.8 13.3Q195.2 26.6 195.2 52Q195.2 59.2 194.6 65.7H116.8V46.9H168.6Q168.6 36.2 163.1 30.5Q157.7 24.8 147.9 24.8Q137.3 24.8 131.4 32.3Q125.6 39.9 125.6 53.8Q125.6 68.8 134.2 76.6Q142.9 84.4 158.9 84.4Q166.1 84.4 173.1 83.7Q180.1 82.9 187.4 81.6L190 107.2Q179.8 109 171.4 109.5Q163 110 156.5 110ZM255.5 110Q228 110 213 95.8Q198 81.5 198 54.8Q198 28.8 210.8 14.4Q223.5 0 246.7 0Q269.4 0 281.8 13.3Q294.2 26.6 294.2 52Q294.2 59.2 293.6 65.7H215.8V46.9H267.6Q267.6 36.2 262.1 30.5Q256.7 24.8 246.9 24.8Q236.3 24.8 230.4 32.3Q224.6 39.9 224.6 53.8Q224.6 68.8 233.2 76.6Q241.9 84.4 257.9 84.4Q265.1 84.4 272.1 83.7Q279.1 82.9 286.4 81.6L289 107.2Q278.8 109 270.4 109.5Q262 110 255.5 110ZM345.8 62.4 339.6 25.9H348.7Q350.3 0 375.8 0Q390.9 0 399 11.1Q407 22.2 407 43.1H380Q380 33.7 376.6 29.6Q373.1 25.5 365.5 25.5Q355.6 25.5 350.7 35.1Q345.8 44.7 345.8 62.4ZM296.4 108V84.8H370.6V108ZM318.8 108V2H341.8L345.8 32.4V108ZM300.4 25.2V2H340.4L342.4 25.2Z"/><rect fill="var(--cursor,#f7ac4d)" x="417" y="87" width="52" height="21"/></svg>`;

const FAVICON = `data:image/svg+xml,${encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" fill="#2840a5"/><text x="6" y="23" font-family="monospace" font-weight="700" font-size="22" fill="#fff">c</text><rect x="20" y="20" width="7" height="3" fill="#f7ac4d"/></svg>')}`;

function pagina({ titulo, u = null, activa = '', cuerpo }, status = 200) {
  const nav = u ? `<nav>
      <a href="/"${activa === '/' ? ' class="activa"' : ''}>Accesos</a>
      ${u.rol === 'admin' ? `<a href="/admin"${activa === '/admin' ? ' class="activa"' : ''}>Administración</a>` : ''}
      <a href="/perfil" class="${activa === '/perfil' ? 'activa' : ''}" title="Tu perfil: GitHub y contraseña">${esc(u.nombre.split(' ')[0])}</a>
      <form method="post" action="/salir"><button type="submit">Salir</button></form>
    </nav>` : '';
  const html = `<!DOCTYPE html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${esc(titulo)} · Panel de miembros del CEER</title>
<link rel="icon" href="${FAVICON}">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/@fontsource/cascadia-code@5.3.0/index.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/@fontsource/cascadia-code@5.3.0/600.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/@fontsource/cascadia-code@5.3.0/700.css" rel="stylesheet">
<style>${CSS}</style></head>
<body>
<header><div class="contenedor">
  <a class="marca" href="/"><span class="logo">${LOGO}</span><span class="sep" aria-hidden="true"></span><span class="producto">Panel de miembros</span></a>
  ${nav}
</div></header>
<main><div class="contenedor">${cuerpo}</div></main>
<footer><div class="contenedor">
  <div class="firma"><span class="logo">${LOGO}</span><span>Centro de Estudios Económicos Renovación</span></div>
  <div class="links"><a class="mono" href="https://x.com/ceerenovacion" target="_blank" rel="noopener">@ceerenovacion</a>
    <a class="mono" href="mailto:ceerenovacion@gmail.com">ceerenovacion@gmail.com</a>
    <a href="https://estudiosrenovacion.com" target="_blank" rel="noopener">estudiosrenovacion.com</a></div>
</div></footer>
</body></html>`;
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'same-origin'
    }
  });
}

const CSS = `
:root{--azul-600:#2840a5;--azul-700:#1f3385;--azul-200:#c0d0f9;--cian-700:#138282;--lima-300:#e6f05a;--rojo-600:#af3e30;
--n50:#f6f7f9;--n200:#dfe1e5;--n400:#9c9ea5;--n600:#5d6069;--tinta:#171a24;
--mono:"Cascadia Code",ui-monospace,monospace;--sans:Inter,system-ui,sans-serif}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--n50);color:var(--tinta);font-family:var(--sans);font-size:16px;line-height:1.5;hyphens:manual}
a{color:inherit}
.mono{font-family:var(--mono)}
.contenedor{width:100%;max-width:1120px;margin:0 auto;padding:0 32px}
header{flex-shrink:0;background:#fff;border-bottom:1px solid var(--n200)}
header .contenedor{height:64px;display:flex;align-items:center;justify-content:space-between;gap:24px}
.marca{display:flex;align-items:baseline;gap:14px;text-decoration:none}
.marca .logo{display:block;width:102px;height:24px;color:var(--azul-600);--cursor:#d6810c}
.marca .sep{align-self:center;width:1px;height:24px;background:var(--n200)}
.marca .producto{font-weight:600;font-size:20px;line-height:1;white-space:nowrap}
nav{display:flex;align-items:center;gap:24px;font-size:14px;color:var(--n600)}
nav a{text-decoration:none;padding:4px 0;border-bottom:2px solid transparent;white-space:nowrap}
nav a:hover{color:var(--tinta)}
nav a.activa{color:var(--tinta);font-weight:600;border-bottom-color:var(--azul-600)}
nav form{margin:0}
nav button{font:inherit;color:inherit;background:none;border:0;padding:4px 0;cursor:pointer}
nav button:hover{color:var(--tinta)}
main{flex:1 0 auto;padding:48px 0 64px}
main .contenedor > :last-child, section:last-child{margin-bottom:0}
h1{margin:0 0 16px;font-family:var(--mono);font-weight:700;font-size:44px;line-height:52px;letter-spacing:-.01em}
h1.chico{font-size:32px;line-height:40px}
h1.espacio{margin-bottom:24px}
.estado-gh{font-size:13px;color:var(--n600);margin-top:4px}
.bajada{margin:0 0 40px;font-size:18px;line-height:28px;color:var(--n600)}
.bajada.sin{margin:0}
section{margin:0 0 48px}
h2{margin:0 0 20px;font-family:var(--mono);font-weight:700;font-size:26px;line-height:32px}
h3.sub{margin:32px 0 12px;font-family:var(--mono);font-weight:700;font-size:18px;line-height:24px}
.accesos{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.acceso{position:relative;display:flex;flex-direction:column;background:#fff;border:1px solid var(--n200);padding:24px;min-height:190px;transition:border-color .15s}
.acceso:hover,.acceso:focus-within{border-color:var(--azul-600)}
.acceso .principal{text-decoration:none;outline:none}
.acceso .principal::after{content:"";position:absolute;inset:0}
.acceso:hover h3,.acceso .principal:focus-visible{text-decoration:underline;text-decoration-color:var(--azul-600);text-underline-offset:4px}
.acceso .pie-acceso{margin-top:auto;padding-top:16px;display:flex;align-items:baseline;justify-content:space-between;gap:12px}
.acceso .repo{position:relative;z-index:1;flex-shrink:0;font-family:var(--mono);font-size:13px;color:var(--n600);text-decoration:none;padding:2px 0;border-bottom:1px solid var(--n200)}
.acceso .repo:hover,.acceso .repo:focus-visible{color:var(--azul-600);border-bottom-color:var(--azul-600);outline:none}
.acceso .tipo{font-size:13px;line-height:18px;height:22px;color:var(--n600);margin:0 0 8px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.acceso h3{margin:0 0 8px;font-family:var(--mono);font-weight:700;font-size:20px;line-height:26px}
.acceso p{margin:0;font-size:15px;line-height:22px;color:var(--n600)}
.acceso .destino{min-width:0;font-family:var(--mono);font-size:13px;color:var(--azul-600);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.acceso .destino::before{content:"// ";color:var(--cian-700)}
.acceso.pendiente{border-style:dashed}
.etiqueta{font-size:12px;font-weight:600;line-height:1;padding:5px 8px;background:var(--lima-300);color:var(--tinta)}
.caja{background:#fff;border-top:3px solid var(--tinta);padding:32px}
.caja.angosta{max-width:480px;margin:0 auto}
.caja.editor{border-top:1px solid var(--n200);border:1px solid var(--n200);padding:20px 24px;margin:0 0 12px;position:relative}
.form{display:flex;flex-direction:column;gap:16px}
.form label{display:flex;flex-direction:column;gap:6px;font-size:14px;font-weight:600}
.form .ayuda{font-weight:400;color:var(--n600)}
.form input,.form select{font:inherit;font-weight:400;font-size:16px;padding:10px 12px;border:1px solid var(--n200);background:#fff;color:var(--tinta);border-radius:0;width:100%}
.form input:focus,.form select:focus{outline:2px solid var(--azul-600);outline-offset:-1px;border-color:var(--azul-600)}
.form.fila,.acceso-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;align-items:end}
.acceso-form .ancho{grid-column:span 2}
.botones{display:flex;align-items:end}
.boton{font:inherit;font-weight:600;font-size:15px;background:var(--azul-600);color:#fff;border:0;padding:12px 20px;cursor:pointer;text-decoration:none;display:inline-block}
.boton:hover{background:var(--azul-700)}
.link{font:inherit;font-size:14px;background:none;border:0;padding:0;color:var(--azul-600);cursor:pointer;text-decoration:underline;text-underline-offset:3px}
.eliminar-acceso{position:absolute;top:20px;right:24px;margin:0}
.msj{margin:0 0 24px;padding:14px 16px;font-size:15px;background:#fff;border-left:3px solid var(--azul-600)}
.msj.error{border-left-color:var(--rojo-600);color:var(--rojo-600)}
.msj.clave{border-left-color:var(--tinta);background:#fde3c0}
.msj.clave p{margin:0 0 8px}.msj.clave p:last-child{margin:0}
.tabla{overflow-x:auto;background:#fff;border:1px solid var(--n200)}
table{width:100%;border-collapse:collapse;font-size:15px}
th{text-align:left;font-size:13px;font-weight:600;color:var(--n600);padding:12px 16px;border-bottom:1px solid var(--n200)}
td{padding:12px 16px;border-bottom:1px solid var(--n200);vertical-align:middle}
tr:last-child td{border-bottom:0}
tr.inactiva td{color:var(--n400)}
th.num,td.num{text-align:right}
.texto{margin:0 0 16px;font-size:15px;color:var(--n600)}
.texto.sin{margin:0}
.acciones{display:flex;gap:16px;justify-content:flex-end;white-space:nowrap}
.acciones form{margin:0}
footer{flex-shrink:0;background:var(--azul-600);color:#fff}
footer .contenedor{min-height:96px;display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap;padding-top:24px;padding-bottom:24px}
footer .firma{display:flex;align-items:baseline;gap:12px;font-size:15px}
footer .firma .logo{display:block;width:119px;height:28px;color:#fff;--cursor:#f7ac4d}
footer .links{display:flex;gap:8px 24px;flex-wrap:wrap;font-size:14px;color:var(--azul-200)}
footer .links a{text-decoration:none}
footer .links a:hover{color:#fff}
@media (max-width:720px){
  .contenedor{padding:0 20px}
  h1{font-size:34px;line-height:42px}
  .marca{gap:10px}.marca .producto{font-size:16px}
  nav{gap:16px}nav .ocultable{display:none}
  .caja{padding:24px}
  .acceso-form .ancho{grid-column:auto}
  .eliminar-acceso{position:static;margin-top:12px}
}`;

/* ---------------- utilidades ---------------- */
function esc(t) {
  return String(t ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function host(url) {
  if (url.startsWith('/')) return url;
  try { const u = new URL(url); return u.host.replace(/^www\./, '') + (u.pathname.length > 1 ? u.pathname.split('/').slice(0, 2).join('/') : ''); }
  catch { return url; }
}
const texto = (t, status = 200) => new Response(t, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } });
const redirigir = (to, extra = {}) => new Response(null, { status: 303, headers: { location: to, 'cache-control': 'no-store', ...extra } });
function mismoOrigen(request, url) {
  const o = request.headers.get('origin');
  return !o || o === url.origin;
}
function leerCookie(request, nombre) {
  const c = request.headers.get('cookie') || '';
  const m = c.split(/;\s*/).find((x) => x.startsWith(nombre + '='));
  return m ? m.slice(nombre.length + 1) : '';
}
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
function hexAleatorio(n) { return hex(crypto.getRandomValues(new Uint8Array(n))); }
async function sha256(t) { return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t))); }
async function pbkdf2(clave, salHex) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(clave), 'PBKDF2', false, ['deriveBits']);
  const sal = new Uint8Array(salHex.match(/../g).map((h) => parseInt(h, 16)));
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: sal, iterations: ITER }, k, 256));
}
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function claveTemporal() {
  const abc = 'abcdefghjkmnpqrstuvwxyz23456789';
  const b = crypto.getRandomValues(new Uint8Array(12));
  const s = [...b].map((x) => abc[x % abc.length]).join('');
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`;
}
