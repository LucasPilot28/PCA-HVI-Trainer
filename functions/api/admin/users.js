// functions/api/admin/users.js  ->  GET /api/admin/users
// Header: X-Admin-Secret: <ADMIN_SECRET>
// Respuesta 200: { users: [{ id, username, approved, created_at }, ...] }

import { isAdminRequest, jsonResponse, errorResponse, withErrorHandling } from '../../../lib/auth.js';

export const onRequestGet = withErrorHandling(async (context) => {
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

  const { results } = await env.DB.prepare(
    'SELECT id, username, approved, created_at FROM users ORDER BY created_at DESC'
  ).all();

  return jsonResponse({ users: results });
});
