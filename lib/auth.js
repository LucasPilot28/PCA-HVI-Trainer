// lib/auth.js
// Funciones compartidas por los endpoints en /functions/api/*.
// Este archivo vive FUERA de /functions a propósito: Cloudflare Pages
// convierte cada archivo dentro de /functions en una ruta HTTP, así que
// el código compartido debe ir en otra carpeta para no quedar expuesto
// como endpoint por accidente.

// ---------- Config ----------

// Iteraciones de PBKDF2 para el hash de contraseñas.
//
// Cloudflare Pages Functions (plan gratuito) solo permite 10ms de CPU
// por solicitud. Medido en un entorno equivalente, hashear una contraseña
// tarda aprox. 0.5ms por cada 1.000 iteraciones, así que:
//   10.000 iteraciones  ≈  5ms   (holgado en el plan gratuito) <- valor usado aquí
//   50.000 iteraciones  ≈ 24ms   (excede el límite gratuito)
//  100.000 iteraciones  ≈ 55ms   (excede el límite gratuito)
// 10.000 es además el mínimo recomendado por NIST SP 800-132 para
// PBKDF2-HMAC-SHA256, así que sigue siendo un valor legítimo, no un atajo
// inseguro. Si en algún momento pasas tu proyecto de Cloudflare al plan
// "Paid" (5 USD/mes, sube el límite de CPU a varios segundos), puedes subir
// este número con tranquilidad (por ejemplo a 100000) para más margen.
export const PBKDF2_ITERATIONS = 10000;

// Cuánto dura una sesión antes de tener que volver a iniciar sesión.
export const SESSION_DURATION_SECONDS = 60 * 60 * 24 * 30; // 30 días

export const USERNAME_MIN = 3;
export const USERNAME_MAX = 40;
export const PASSWORD_MIN = 6;
export const PASSWORD_MAX = 256;
export const PROGRESS_MAX_BYTES = 900000; // margen de seguridad bajo el límite de fila de D1

// ---------- Utilidades básicas ----------

export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

export function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

// Envuelve un handler de Pages Function para que cualquier error
// inesperado (por ejemplo: el binding D1 "DB" no está configurado)
// devuelva un mensaje claro en vez de un 500 genérico sin explicación.
export function withErrorHandling(handler) {
  return async (context) => {
    try {
      return await handler(context);
    } catch (err) {
      console.error(err);
      return errorResponse(
        'Error del servidor. Verifica que la base de datos D1 esté creada y enlazada al proyecto de Pages (binding llamado "DB").',
        500
      );
    }
  };
}

// ---------- Validación ----------

export function validateUsername(username) {
  if (!username) return 'Ingresa un nombre de usuario.';
  if (username.length < USERNAME_MIN) return `El nombre de usuario debe tener al menos ${USERNAME_MIN} caracteres.`;
  if (username.length > USERNAME_MAX) return `El nombre de usuario es muy largo (máx. ${USERNAME_MAX} caracteres).`;
  return null;
}

export function validatePassword(password) {
  if (!password) return 'Ingresa una contraseña.';
  if (password.length < PASSWORD_MIN) return `La contraseña debe tener al menos ${PASSWORD_MIN} caracteres.`;
  if (password.length > PASSWORD_MAX) return 'La contraseña es demasiado larga.';
  return null;
}

// ---------- Codificación hex <-> bytes ----------

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bufToHex(bytes.buffer);
}

// Comparación en tiempo constante para no filtrar por timing (se usa tanto
// para comparar hashes de contraseña como la clave de administrador).
export function timingSafeEqualString(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ---------- Contraseñas (PBKDF2-SHA256 vía Web Crypto, nativo en Workers) ----------

export async function hashPassword(password, iterations = PBKDF2_ITERATIONS) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return { hash: bufToHex(bits), salt: bufToHex(salt.buffer), iterations };
}

export async function verifyPassword(password, storedHashHex, storedSaltHex, iterations) {
  const salt = hexToBytes(storedSaltHex);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return timingSafeEqualString(bufToHex(bits), storedHashHex);
}

// ---------- Sesiones ----------

export function createSessionToken() {
  return randomHex(32); // 256 bits, suficiente entropía para un token de sesión
}

export function getBearerToken(request) {
  const header = request.headers.get('Authorization') || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

// Valida el token del header Authorization contra D1.
// Devuelve { user_id, username } o null si no hay sesión válida.
// Si la sesión existe pero ya expiró, la borra de paso.
// También revisa "approved": si el administrador revocó el acceso después
// de que la persona ya había iniciado sesión, esto la desconecta de
// inmediato (no espera a que expire el token).
export async function getSession(db, request) {
  const token = getBearerToken(request);
  if (!token) return null;

  const row = await db
    .prepare(
      `SELECT sessions.user_id AS user_id, sessions.expires_at AS expires_at,
              users.username AS username, users.approved AS approved
       FROM sessions JOIN users ON users.id = sessions.user_id
       WHERE sessions.token = ?`
    )
    .bind(token)
    .first();

  if (!row) return null;

  if (row.expires_at < nowSeconds()) {
    await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }

  if (!row.approved) return null;

  return { user_id: row.user_id, username: row.username };
}

// ---------- Administración ----------

// Compara la clave secreta enviada en el header X-Admin-Secret contra la
// variable de entorno ADMIN_SECRET (configurada en Cloudflare Pages ->
// Settings -> Environment variables). No tiene relación con las cuentas
// de usuario: es un secreto único que solo tú conoces.
export function isAdminRequest(request, env) {
  if (!env.ADMIN_SECRET) return false;
  const provided = request.headers.get('X-Admin-Secret') || '';
  return timingSafeEqualString(provided, env.ADMIN_SECRET);
}

  return { user_id: row.user_id, username: row.username };
}
