-- Base del Panel de miembros del CEER (D1: panel-miembros-ceer-db)
CREATE TABLE IF NOT EXISTS usuarios (
  usuario       TEXT PRIMARY KEY,           -- en minúsculas, sin espacios
  nombre        TEXT NOT NULL,
  rol           TEXT NOT NULL DEFAULT 'miembro',  -- 'admin' | 'miembro'
  hash          TEXT NOT NULL,              -- PBKDF2-SHA256, 100.000 iteraciones, hex
  sal           TEXT NOT NULL,              -- hex
  debe_cambiar  INTEGER NOT NULL DEFAULT 1, -- 1: tiene que cambiar la clave al entrar
  activo        INTEGER NOT NULL DEFAULT 1,
  fallos        INTEGER NOT NULL DEFAULT 0,
  bloqueo_hasta INTEGER NOT NULL DEFAULT 0, -- epoch ms
  creado        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  github        TEXT,                       -- usuario de GitHub que carga cada miembro en /perfil
  github_estado TEXT,                       -- resultado de la última revisión de acceso a los repos
  github_revisado INTEGER NOT NULL DEFAULT 0 -- epoch ms
);
CREATE TABLE IF NOT EXISTS sesiones (
  token_hash TEXT PRIMARY KEY,              -- SHA-256 del token de la cookie
  usuario    TEXT NOT NULL,
  vence      INTEGER NOT NULL               -- epoch ms
);
-- Los enlaces viven en la base (no en el repo, que es público) y se editan desde /admin
CREATE TABLE IF NOT EXISTS accesos (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  seccion     TEXT NOT NULL,
  titulo      TEXT NOT NULL,
  descripcion TEXT NOT NULL DEFAULT '',
  url         TEXT NOT NULL,
  tipo        TEXT NOT NULL DEFAULT '',
  repo        TEXT,                         -- dueño/nombre en GitHub (para el enlace "repo")
  estado      TEXT NOT NULL DEFAULT 'activo', -- 'activo' | 'pendiente'
  orden       INTEGER NOT NULL DEFAULT 0
);
