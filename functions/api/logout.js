// functions/api/register.js  ->  POST /api/register
// Body: { username, password }
// Respuesta 200: { pending: true, username }
//
// La cuenta se crea pero queda SIN aprobar (approved = 0) y sin sesión
// activa. Un administrador debe aprobarla desde el panel (admin.html)
// antes de que la persona pueda iniciar sesión.

import {
  hashPassword,
  jsonResponse,
  errorResponse,
  withErrorHandling,
  nowSeconds,
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

  await env.DB.prepare(
    'INSERT INTO users (username, password_hash, password_salt, password_iterations, approved, created_at) VALUES (?, ?, ?, ?, 0, ?)'
  )
    .bind(username, hash, salt, iterations, now)
    .run();

  return jsonResponse({ pending: true, username });
});
