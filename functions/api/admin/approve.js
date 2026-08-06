// functions/api/admin/approve.js  ->  POST /api/admin/approve
// Header: X-Admin-Secret: <ADMIN_SECRET>
// Body: { username, approved: true|false }
// Respuesta 200: { ok: true, username, approved }
//
// Revocar acceso (approved:false) desconecta a la persona de inmediato en
// su próxima solicitud, sin esperar a que expire su sesión: getSession()
// en lib/auth.js revisa el estado "approved" en cada solicitud.

import { isAdminRequest, jsonResponse, errorResponse, withErrorHandling } from '../../../lib/auth.js';

export const onRequestPost = withErrorHandling(async (context) => {
  const { request, env } = context;

  if (!env.DB) {
    return errorResponse('Falta configurar la base de datos D1 (binding "DB") en este proyecto de Pages.', 500);
  }
  if (!env.ADMIN_SECRET) {
    return errorResponse('Falta configurar la variable de entorno ADMIN_SECRET en este proyecto de Pages.', 500);
  }
  if (!isAdminRequest(request, env)) {
    return errorResponse('No autorizado.', 401);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return errorResponse('Cuerpo de la solicitud inválido.', 400);
  }

  const username = (body.username || '').trim();
  const approved = body.approved ? 1 : 0;
  if (!username) {
    return errorResponse('Falta el nombre de usuario.', 400);
  }

  const result = await env.DB.prepare('UPDATE users SET approved = ? WHERE username = ?')
    .bind(approved, username)
    .run();

  if (result.meta.changes === 0) {
    return errorResponse('No se encontró ese usuario.', 404);
  }

  return jsonResponse({ ok: true, username, approved: !!approved });
});
