// functions/api/me.js  ->  GET /api/me
// Header: Authorization: Bearer <token>
// Respuesta 200: { username, progress }
// Se usa para reanudar sesión automáticamente cuando la persona vuelve
// al sitio (el navegador guarda el token, no la contraseña).

import { getSession, jsonResponse, errorResponse, withErrorHandling } from '../../lib/auth.js';

export const onRequestGet = withErrorHandling(async (context) => {
  const { request, env } = context;

  if (!env.DB) {
    return errorResponse('Falta configurar la base de datos D1 (binding "DB") en este proyecto de Pages.', 500);
  }

  const session = await getSession(env.DB, request);
  if (!session) {
    return errorResponse('Sesión inválida o expirada.', 401);
  }

  const progRow = await env.DB.prepare('SELECT data FROM progress WHERE user_id = ?').bind(session.user_id).first();

  return jsonResponse({ username: session.username, progress: progRow ? progRow.data : null });
});
