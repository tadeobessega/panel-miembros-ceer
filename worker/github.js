/* Acceso de los miembros a los repos de GitHub.
   Usa el secreto GITHUB_TOKEN (token de la cuenta dueña de los repos, con permiso para
   administrar colaboradores). Cada miembro con usuario de GitHub cargado queda invitado
   como colaborador con permiso de escritura en TODOS los repos de la cuenta.
   GitHub manda la invitación por mail: el miembro tiene que aceptarla. */

const API = 'https://api.github.com';
export const DUENO = 'tadeobessega';

function gh(env, path, init = {}) {
  return fetch(API + path, {
    ...init,
    headers: {
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      'user-agent': 'panel-miembros-ceer',
      ...(env.GITHUB_TOKEN ? { authorization: `Bearer ${env.GITHUB_TOKEN}` } : {}),
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...(init.headers || {})
    }
  });
}

/* Devuelve el login con la capitalización de GitHub, o null si no existe. */
export async function usuarioGitHub(env, login) {
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(login)) return null;
  const r = await gh(env, `/users/${encodeURIComponent(login)}`);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`GitHub no respondió (${r.status}). Probá de nuevo en un rato.`);
  const d = await r.json();
  return d.type === 'User' ? d.login : null;
}

/* Repos propios de la cuenta (privados incluidos si el token los ve). */
export async function reposDeLaCuenta(env) {
  const repos = [];
  for (let page = 1; page <= 10; page++) {
    const r = await gh(env, `/user/repos?affiliation=owner&per_page=100&page=${page}`);
    if (!r.ok) throw new Error(`GitHub respondió ${r.status} al listar repos`);
    const lote = await r.json();
    repos.push(...lote.filter((x) => !x.archived && x.owner.login.toLowerCase() === DUENO).map((x) => x.name));
    if (lote.length < 100) break;
  }
  return repos;
}

/* Invita (o confirma) al miembro en todos los repos. Devuelve un texto de estado. */
export async function darAcceso(env, login) {
  if (!env.GITHUB_TOKEN) return 'Pendiente: falta configurar el token de GitHub del panel';
  if (login.toLowerCase() === DUENO) return 'Dueño de los repos';
  const repos = await reposDeLaCuenta(env);
  let invitados = 0, yaEstaba = 0, fallos = [];
  for (const repo of repos) {
    const r = await gh(env, `/repos/${DUENO}/${repo}/collaborators/${encodeURIComponent(login)}`, {
      method: 'PUT',
      body: JSON.stringify({ permission: 'push' })
    });
    if (r.status === 201) invitados++;
    else if (r.status === 204) yaEstaba++;
    else fallos.push(`${repo} (${r.status})`);
  }
  const partes = [];
  if (yaEstaba) partes.push(`colaborador en ${yaEstaba}`);
  if (invitados) partes.push(`invitación enviada en ${invitados}, falta aceptarla desde el mail de GitHub`);
  if (fallos.length) partes.push(`no se pudo en ${fallos.join(', ')}`);
  return `${repos.length} repos: ${partes.join('; ') || 'sin cambios'}`;
}

/* Saca al miembro (y sus invitaciones pendientes) de todos los repos. */
export async function quitarAcceso(env, login) {
  if (!env.GITHUB_TOKEN || !login || login.toLowerCase() === DUENO) return;
  const repos = await reposDeLaCuenta(env);
  for (const repo of repos) {
    await gh(env, `/repos/${DUENO}/${repo}/collaborators/${encodeURIComponent(login)}`, { method: 'DELETE' });
    const inv = await gh(env, `/repos/${DUENO}/${repo}/invitations?per_page=100`);
    if (inv.ok) {
      for (const i of await inv.json()) {
        if (i.invitee && i.invitee.login.toLowerCase() === login.toLowerCase()) {
          await gh(env, `/repos/${DUENO}/${repo}/invitations/${i.id}`, { method: 'DELETE' });
        }
      }
    }
  }
}

/* Baja un archivo de un release. Con token funciona aunque el repo sea privado: se pide el asset por la API
   y se sigue a mano la redirección a la URL firmada (sin mandar el token a otro dominio). */
export async function assetRelease(env, repo, tag, nombre) {
  if (env.GITHUB_TOKEN) {
    const r = await gh(env, `/repos/${DUENO}/${repo}/releases/tags/${tag}`);
    if (!r.ok) return null;
    const a = ((await r.json()).assets || []).find((x) => x.name === nombre);
    if (!a) return null;
    const d = await gh(env, `/repos/${DUENO}/${repo}/releases/assets/${a.id}`, { headers: { accept: 'application/octet-stream' }, redirect: 'manual' });
    if (d.status >= 300 && d.status < 400 && d.headers.get('location')) return fetch(d.headers.get('location'));
    return d.ok ? d : null;
  }
  const r = await fetch(`https://github.com/${DUENO}/${repo}/releases/download/${tag}/${nombre}`, { redirect: 'follow' });
  return r.ok ? r : null;
}

/* Estado de los backups que sube la PC (scripts/backup_repos.ps1 del repo ipceer). */
export async function estadoBackups(env) {
  try {
    const r = await assetRelease(env, 'ipceer', 'sepa-archivo', 'estado_backups.json');
    if (!r) return null;
    return JSON.parse((await r.text()).replace(/^\uFEFF/, ''));
  } catch {
    return null;
  }
}

/* Chequeo del token (sin datos sensibles): si está, si es válido, de quién es y si puede administrar los repos. */
export async function chequeoToken(env) {
  if (!env.GITHUB_TOKEN) return { token: false };
  const u = await gh(env, '/user');
  if (!u.ok) return { token: true, valido: false, status: u.status };
  const login = (await u.json()).login;
  let repos = [], error = null;
  try { repos = await reposDeLaCuenta(env); } catch (e) { error = e.message; }
  let privados = 0, conAdmin = 0;
  for (const repo of repos) {
    const r = await gh(env, `/repos/${DUENO}/${repo}`);
    const d = r.ok ? await r.json() : null;
    if (d && d.private) privados++; if (d && d.permissions && d.permissions.admin) conAdmin++;
  }
  const b = await assetRelease(env, 'ipceer', 'sepa-archivo', 'estado_backups.json');
  return { token: true, valido: true, cuenta: login, es_dueno: (login || '').toLowerCase() === DUENO, repos: repos.length, privados, con_permiso_admin: conAdmin, backups_legibles: !!b, error };
}
