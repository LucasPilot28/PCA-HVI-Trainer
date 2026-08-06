// functions/api/login.js  ->  POST /api/login
// Body: { username, password }
// Respuesta 200: { token, username, progress }  (progress es un string JSON o null)

import {
  verifyPassword,
  createSessionToken,
  jsonResponse,
  errorResponse,
  withErrorHandling,
  nowSeconds,
  SESSION_DURATION_SECONDS,
} from '../../lib/auth.js';

export const onRequestPost = withErrorHandling(async (context) => {
  const { request, env } = context;

  if (!env.DB) {
    return errorResponse('Falta configurar la base de datos D1 (binding "DB") en este proyecto de Pages.', 500);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return errorResponse('Cuerpo de la solicitud inválido.', 400);
  }

  const username = (body.username || '').trim();
  const password = body.password || '';

  if (!username || !password) {
    return errorResponse('Usuario o contraseña incorrectos.', 401);
  }

  const user = await env.DB.prepare(
    'SELECT id, username, password_hash, password_salt, password_iterations, approved FROM users WHERE username = ?'
  )
    .bind(username)
    .first();

  // Mensaje deliberadamente genérico: no revelamos si falló el usuario o la clave.
  if (!user) {
    return errorResponse('Usuario o contraseña incorrectos.', 401);
  }

  const ok = await verifyPassword(password, user.password_hash, user.password_salt, user.password_iterations);
  if (!ok) {
    return errorResponse('Usuario o contraseña incorrectos.', 401);
  }

  if (!user.approved) {
    return errorResponse('Tu cuenta existe, pero todavía no ha sido aprobada por el administrador.', 403);
  }

  const now = nowSeconds();
  const token = createSessionToken();
  const expiresAt = now + SESSION_DURATION_SECONDS;
  await env.DB.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(token, user.id, now, expiresAt)
    .run();

  const progRow = await env.DB.prepare('SELECT data FROM progress WHERE user_id = ?').bind(user.id).first();

  return jsonResponse({ token, username: user.username, progress: progRow ? progRow.data : null });
});
