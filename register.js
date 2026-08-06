// functions/api/register.js  ->  POST /api/register
// Body: { username, password }
// Respuesta 200: { token, username, progress: null }

import {
  hashPassword,
  createSessionToken,
  jsonResponse,
  errorResponse,
  withErrorHandling,
  nowSeconds,
  SESSION_DURATION_SECONDS,
  validateUsername,
  validatePassword,
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

  const usernameError = validateUsername(username);
  if (usernameError) return errorResponse(usernameError, 400);

  const passwordError = validatePassword(password);
  if (passwordError) return errorResponse(passwordError, 400);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) {
    return errorResponse('Ese nombre de usuario ya está en uso.', 409);
  }

  const { hash, salt, iterations } = await hashPassword(password);
  const now = nowSeconds();

  const insertResult = await env.DB.prepare(
    'INSERT INTO users (username, password_hash, password_salt, password_iterations, created_at) VALUES (?, ?, ?, ?, ?)'
  )
    .bind(username, hash, salt, iterations, now)
    .run();

  const userId = insertResult.meta.last_row_id;

  const token = createSessionToken();
  const expiresAt = now + SESSION_DURATION_SECONDS;
  await env.DB.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(token, userId, now, expiresAt)
    .run();

  return jsonResponse({ token, username, progress: null });
});
