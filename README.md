# Panel de miembros del CEER

Página interna del Centro de Estudios Económicos Renovación con los accesos del equipo
(sitio, tableros, herramientas, Drive y documentos). Cada miembro entra con su usuario y
contraseña.

## Cómo funciona

| Pieza | Qué es |
|---|---|
| `worker/index.js` | Worker de Cloudflare: arma todas las páginas en el servidor |
| `worker/schema.sql` | Tablas de la base D1 `panel-miembros-ceer-db` |
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
| `/clave` | Cambiar la contraseña propia |
| `/admin` | Solo administradores: crear cuentas, restablecer claves, activar o desactivar, editar accesos |
| `/salir` | Cierra la sesión |

## Deploy

Cloudflare (Workers Builds) está conectado al repo: cada push a `main` publica.
Deploy command: `npx wrangler deploy`.

Para crear las tablas en una base nueva:

```
npx wrangler d1 execute panel-miembros-ceer-db --remote --file worker/schema.sql
```
