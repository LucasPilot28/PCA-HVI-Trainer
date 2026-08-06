// functions/api/progress.js  ->  GET/POST /api/progress
// Header: Authorization: Bearer <token>
//
// GET  -> { progress }               (progress es un string JSON o null)
// POST -> body: { data: "<json>" }   -> { ok: true }

import { getSession, jsonResponse, errorResponse, withErrorHandling, nowSeconds, PROGRESS_MAX_BYTES } from '../../lib/auth.js';

export const onRequestGet = withErrorHandling(async (context) => {
  const { request, env } = context;

  if (!env.DB) {
    return errorResponse('Falta configurar la base de datos D1 (binding "DB") en este proyecto de Pages.', 500);
  }

  const session = await getSession(env.DB, request);
  if (!session) {
    return errorResponse('Sesión inválida o expirada.', 401);
  }

  const row = await env.DB.prepare('SELECT data FROM progress WHERE user_id = ?').bind(session.user_id).first();
  return jsonResponse({ progress: row ? row.data : null });
});

export const onRequestPost = withErrorHandling(async (context) => {
  const { request, env } = context;

  if (!env.DB) {
    return errorResponse('Falta configurar la base de datos D1 (binding "DB") en este proyecto de Pages.', 500);
  }

  const session = await getSession(env.DB, request);
  if (!session) {
    return errorResponse('Sesión inválida o expirada.', 401);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return errorResponse('Cuerpo de la solicitud inválido.', 400);
  }

  const data = typeof body.data === 'string' ? body.data : JSON.stringify(body.data ?? null);

  if (data.length > PROGRESS_MAX_BYTES) {
    return errorResponse('El progreso es demasiado grande para guardar.', 413);
  }

  const now = nowSeconds();
  await env.DB.prepare(
    `INSERT INTO progress (user_id, data, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`
  )
    .bind(session.user_id, data, now)
    .run();

  return jsonResponse({ ok: true });
});
