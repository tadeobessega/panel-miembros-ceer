# Panel de miembros del CEER

Página interna del Centro de Estudios Económicos Renovación con los accesos del equipo
(sitio, tableros, herramientas, Drive y documentos). Cada miembro entra con su usuario y
contraseña.

## Cómo funciona

| Pieza | Qué es |
|---|---|
| `worker/index.js` | Worker de Cloudflare: arma todas las páginas en el servidor |
| `worker/schema.sql` | Tablas de la base D1 `panel-miembros-ceer-db` |
| `worker/github.js` | Acceso de los miembros a los repos de GitHub y estado de los backups |
| `public/<ruta>/index.html` | Páginas del CEER publicadas dentro del panel (solo con sesión) |
| `wrangler.jsonc` | Configuración del Worker |

- **Sin sesión no sale ningún enlace**: el HTML del panel se arma recién después de validar la cookie.
- **Los enlaces no están en el repo** (que es público): viven en la tabla `accesos` y se editan desde `/admin`.
- Contraseñas con PBKDF2-SHA256 (100.000 iteraciones). Cookie `HttpOnly`, `Secure`, `SameSite=Lax`, 30 días.
- 5 intentos fallidos bloquean la cuenta 15 minutos.
- Las cuentas nuevas y las claves restablecidas usan una clave temporal: al entrar, el miembro tiene que elegir la suya.

## Rutas

| Ruta | Qué hace |
|---|---|
| `/login` | Ingreso |
| `/` | Accesos |
| `/perfil` | Usuario de GitHub de cada miembro y acceso a la contraseña |
| `/clave` | Cambiar la contraseña propia |
| `/intercambio-comercial-provincial/` | Página de exportaciones por provincia (OPEX 2002-2025) |
| `/admin` | Solo administradores: crear cuentas, restablecer claves, activar o desactivar, editar accesos |
| `/salir` | Cierra la sesión |

## Deploy

Cloudflare (Workers Builds) está conectado al repo: cada push a `main` publica.
Deploy command: `npx wrangler deploy`.

Para crear las tablas en una base nueva:

```
npx wrangler d1 execute panel-miembros-ceer-db --remote --file worker/schema.sql
```

## Acceso a los repos de GitHub

Cada miembro carga su usuario de GitHub en `/perfil` y queda invitado con permiso de escritura en
todos los repos de `tadeobessega` (GitHub le manda la invitación por mail). Si se desactiva o
elimina la cuenta, se lo saca de los repos. Un cron por hora revisa a un miembro por vez, así los
repos nuevos también les llegan.

Hace falta el secreto `GITHUB_TOKEN` en el Worker (Settings, Variables and Secrets): un token de
`tadeobessega` con permiso para administrar colaboradores (classic con `repo`, o fine-grained con
Administration: read and write en todos los repos). Sin el token, el perfil guarda el usuario y
queda pendiente.

## Backups

Los hace la PC de Tadeo todos los días (`scripts/backup_repos.ps1` del repo `ipceer`): un `.bundle`
con toda la historia de cada repo en OneDrive, 30 días más el primero de cada mes. El estado se ve
en `/admin`.

## Páginas dentro del panel

Van en `public/<ruta>/index.html` y se agregan a `PAGINAS` en `worker/index.js`. El Worker pide
sesión antes de servirlas. La de intercambio comercial provincial se arma con los datos agregados de
OPEX 2002-2025 (el CSV de 85 MB no está en el repo).
