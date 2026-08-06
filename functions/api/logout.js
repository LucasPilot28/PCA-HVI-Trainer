// functions/api/logout.js  ->  POST /api/logout
// Header: Authorization: Bearer <token>
// Respuesta 200: { ok: true }  (siempre, incluso si el token ya no existía)

import { getBearerToken, jsonResponse, errorResponse, withErrorHandling } from '../../lib/auth.js';

export const onRequestPost = withErrorHandling(async (context) => {
  const { request, env } = context;

  if (!env.DB) {
    return errorResponse('Falta configurar la base de datos D1 (binding "DB") en este proyecto de Pages.', 500);
  }

  const token = getBearerToken(request);
  if (token) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }
  return jsonResponse({ ok: true });
});
