export default async (request: Request, db: D1Database, session_id: string | false) => {
  if (session_id) {
    await db.prepare(`DELETE FROM sessions WHERE id=?`).bind(session_id).run();
  }

  return new Response(
    `<script>location.href = '/auth/login';</script>`,
    {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
  );
};
