// functions/api/comentarios/[[path]].js
//
// Un solo archivo para las tres rutas, usando el catch-all opcional de
// Pages Functions. Menos archivos que commitear a mano y menos riesgo de
// dejar uno vacío por accidente.
//
//   GET    /api/comentarios?q=<qkey>        -> { comentarios: [...] }
//   POST   /api/comentarios                 -> body { qkey, texto }   -> { ok: true }
//   DELETE /api/comentarios/<id>            -> { ok: true }
//   POST   /api/comentarios/<id>/voto       -> body { dir: 1|0|-1 }   -> { ok: true }
//
// Header en todas: Authorization: Bearer <token>

import {
  getSession,
  jsonResponse,
  errorResponse,
  withErrorHandling,
  nowSeconds,
} from '../../../lib/auth.js';

const TEXTO_MAX = 1200;
const QKEY_MAX = 80;

// Tope por persona y por pregunta. No es antiabuso serio, solo evita que
// una sola cuenta llene el hilo de una pregunta.
const MAX_POR_PREGUNTA = 20;

// Devuelve la sesión o una Response de error ya lista para retornar.
async function exigirSesion(env, request) {
  if (!env.DB) {
    return {
      error: errorResponse(
        'Falta configurar la base de datos D1 (binding "DB") en este proyecto de Pages.',
        500
      ),
    };
  }
  const session = await getSession(env.DB, request);
  if (!session) {
    return { error: errorResponse('Sesión inválida o expirada.', 401) };
  }
  return { session };
}

function segmentos(context) {
  const p = context.params && context.params.path;
  if (!p) return [];
  return Array.isArray(p) ? p : [p];
}

// ---------------------------------------------------------------- GET

export const onRequestGet = withErrorHandling(async (context) => {
  const { request, env } = context;

  const { session, error } = await exigirSesion(env, request);
  if (error) return error;

  const qkey = new URL(request.url).searchParams.get('q');
  if (!qkey || qkey.length > QKEY_MAX) {
    return errorResponse('Falta el identificador de la pregunta.', 400);
  }

  // Un solo viaje a la base: conteo de votos y mi propio voto salen de la
  // misma consulta. Se usa SUM y no MAX para "miVoto" porque MAX sobre
  // {-1, 0} devuelve 0 y perdería los votos en contra; con la clave
  // primaria compuesta hay como máximo una fila mía, así que SUM es exacto.
  const { results } = await env.DB.prepare(
    `SELECT c.id                AS id,
            c.texto             AS texto,
            c.created_at        AS created_at,
            u.username          AS autor,
            COALESCE(SUM(CASE WHEN v.dir =  1 THEN 1 ELSE 0 END), 0) AS up,
            COALESCE(SUM(CASE WHEN v.dir = -1 THEN 1 ELSE 0 END), 0) AS down,
            COALESCE(SUM(CASE WHEN v.user_id = ?1 THEN v.dir ELSE 0 END), 0) AS miVoto
       FROM comments c
       JOIN users u ON u.id = c.user_id
       LEFT JOIN comment_votes v ON v.comment_id = c.id
      WHERE c.qkey = ?2
      GROUP BY c.id
      ORDER BY c.created_at DESC`
  )
    .bind(session.user_id, qkey)
    .all();

  const comentarios = (results || []).map((r) => ({
    id: r.id,
    autor: r.autor,
    autorKey: r.autor, // el front compara contra perfilActual.key, que es el username
    texto: r.texto,
    ts: r.created_at * 1000, // el front usa milisegundos
    up: r.up,
    down: r.down,
    miVoto: r.miVoto,
  }));

  return jsonResponse({ comentarios });
});

// --------------------------------------------------------------- POST
// Sin segmentos -> crear comentario.  Con /<id>/voto -> votar.

export const onRequestPost = withErrorHandling(async (context) => {
  const { request, env } = context;

  const { session, error } = await exigirSesion(env, request);
  if (error) return error;

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return errorResponse('Cuerpo de la solicitud inválido.', 400);
  }

  const partes = segmentos(context);

  // ---- POST /api/comentarios/<id>/voto
  if (partes.length === 2 && partes[1] === 'voto') {
    const commentId = partes[0];
    const dir = Number(body.dir);
    if (![1, 0, -1].includes(dir)) {
      return errorResponse('Voto inválido.', 400);
    }

    const existe = await env.DB.prepare('SELECT id FROM comments WHERE id = ?')
      .bind(commentId)
      .first();
    if (!existe) return errorResponse('El comentario ya no existe.', 404);

    if (dir === 0) {
      await env.DB.prepare(
        'DELETE FROM comment_votes WHERE comment_id = ? AND user_id = ?'
      )
        .bind(commentId, session.user_id)
        .run();
    } else {
      await env.DB.prepare(
        `INSERT INTO comment_votes (comment_id, user_id, dir) VALUES (?, ?, ?)
         ON CONFLICT(comment_id, user_id) DO UPDATE SET dir = excluded.dir`
      )
        .bind(commentId, session.user_id, dir)
        .run();
    }
    return jsonResponse({ ok: true });
  }

  // ---- POST /api/comentarios  (crear)
  if (partes.length !== 0) {
    return errorResponse('Ruta no encontrada.', 404);
  }

  const qkey = typeof body.qkey === 'string' ? body.qkey.trim() : '';
  const texto = typeof body.texto === 'string' ? body.texto.trim() : '';

  if (!qkey || qkey.length > QKEY_MAX) {
    return errorResponse('Falta el identificador de la pregunta.', 400);
  }
  if (!texto) {
    return errorResponse('El comentario está vacío.', 400);
  }
  if (texto.length > TEXTO_MAX) {
    return errorResponse(`El comentario es demasiado largo (máx. ${TEXTO_MAX} caracteres).`, 400);
  }

  const mios = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM comments WHERE qkey = ? AND user_id = ?'
  )
    .bind(qkey, session.user_id)
    .first();
  if (mios && mios.n >= MAX_POR_PREGUNTA) {
    return errorResponse('Ya tienes demasiados comentarios en esta pregunta.', 429);
  }

  await env.DB.prepare(
    'INSERT INTO comments (id, qkey, user_id, texto, created_at) VALUES (?, ?, ?, ?, ?)'
  )
    .bind(crypto.randomUUID(), qkey, session.user_id, texto, nowSeconds())
    .run();

  return jsonResponse({ ok: true });
});

// ------------------------------------------------------------- DELETE

export const onRequestDelete = withErrorHandling(async (context) => {
  const { request, env } = context;

  const { session, error } = await exigirSesion(env, request);
  if (error) return error;

  const partes = segmentos(context);
  if (partes.length !== 1) {
    return errorResponse('Ruta no encontrada.', 404);
  }
  const commentId = partes[0];

  // El user_id va en el WHERE: nadie puede borrar el comentario de otro,
  // aunque adivine el id.
  const res = await env.DB.prepare('DELETE FROM comments WHERE id = ? AND user_id = ?')
    .bind(commentId, session.user_id)
    .run();

  if (!res.meta || res.meta.changes === 0) {
    return errorResponse('No se encontró ese comentario tuyo.', 404);
  }

  // D1 no siempre trae las claves foráneas activas, así que limpiamos los
  // votos a mano en vez de confiar en ON DELETE CASCADE.
  await env.DB.prepare('DELETE FROM comment_votes WHERE comment_id = ?')
    .bind(commentId)
    .run();

  return jsonResponse({ ok: true });
});
