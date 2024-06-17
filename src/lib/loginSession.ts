import uuid from "./uuid";

const loginSession = async (request, db, user_id, type: string | 'json') => {
  let session_id = uuid();
  let message: null|string = null;

  const cookie = request.headers.get('cookie');
  if (cookie) {
    const matches = cookie.match(/session_id=([^\;]+)/);
    if (matches && matches[1]) {
      session_id = matches[1];
    }
  }
  const expires_at = (new Date((new Date).getTime() + 86400 * 31 * 1000)).getTime();
  const session = await db.prepare(`SELECT * FROM sessions WHERE id=?`).bind(session_id).first();
  if (!session) {
    const { count, duration } = <{ count: number, duration: number, }> (await db.prepare(`INSERT INTO sessions (id, user_id, expires_at) VALUES (?1, ?2, ?3)`).bind(session_id, user_id, expires_at).run()).meta;
    if (!duration) {
      message = 'Session insert failed';
    }
  } else {
    const { count, duration } = <{ count: number, duration: number, }> (await db.prepare(`UPDATE sessions SET user_id=?2, expires_at=?3 WHERE id=?1`).bind(session_id, user_id, expires_at).run()).meta;
    if (!duration) {
      message = 'Session update failed';
    }
  }

  if (message) {
    if (type === 'json') {
      return Response.json({
        success: false,
        message,
      });
    } else {
      return new Response(message, {
        headers: {
          'Content-Type': `text/html`,
        },
      })
    }
  }

  if (type === 'json') {
    return Response.json({
      success: true,
      message: 'OK',
    }, {
      headers: {
        'Set-Cookie': `session_id=${session_id}; path=/; expires=${expires_at}`,
      },
    });
  } else {
    return new Response(`
        ${type}
        <script>
        window.location = '/dashboard';
        </script>
      `, {
      headers: {
        'Content-Type': `text/html`,
        'Set-Cookie': `session_id=${session_id}; path=/; expires=${expires_at}`,
      },
    });
  }
};

export default loginSession;