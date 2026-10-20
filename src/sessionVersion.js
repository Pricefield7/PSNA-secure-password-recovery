'use strict';
/**
 * Mount AFTER existing JWT signature verification. Every protected route must
 * check the account's current version; merely adding it to login is insufficient.
 */
async function checkSessionVersion(pool, claims) {
  if (!claims || !['Student', 'Admin'].includes(claims.role) || !claims.email || !Number.isSafeInteger(claims.sessionVersion)) return false;
  const table = claims.role === 'Admin' ? 'users' : 'students';
  const result = await pool.query(
    `SELECT session_version FROM ${table} WHERE LOWER(email)=LOWER($1) LIMIT 1`,
    [claims.email]
  );
  return result.rowCount === 1 && Number(result.rows[0].session_version) === claims.sessionVersion;
}
async function getSessionVersion(pool, role, email) {
  const table = role === 'Admin' ? 'users' : 'students';
  if (!['Admin','Student'].includes(role)) throw new Error('Invalid role');
  const r = await pool.query(`SELECT session_version FROM ${table} WHERE LOWER(email)=LOWER($1) LIMIT 1`,[email]);
  if (r.rowCount !== 1) throw new Error('Account not found');
  return Number(r.rows[0].session_version);
}
module.exports = {checkSessionVersion,getSessionVersion};
