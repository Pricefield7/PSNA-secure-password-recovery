'use strict';
const express = require('express');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const OTP_TTL_MS = 5 * 60 * 1000;
const PROOF_TTL_MS = 5 * 60 * 1000;
const COOLDOWN_MS = 60 * 1000;
const MAX_ATTEMPTS = 5;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const key = () => {
  const secret = process.env.RECOVERY_HMAC_KEY;
  if (!secret || !/^[a-f0-9]{64,}$/i.test(secret)) throw new Error('RECOVERY_HMAC_KEY must contain at least 32 random bytes encoded as hex');
  return Buffer.from(secret,'hex');
};
const hash = (purpose, role, email, value) =>
  crypto.createHmac('sha256',key()).update(JSON.stringify([purpose,role,email,value])).digest('hex');
const normalize = (value) => typeof value === 'string' ? value.trim().toLowerCase() : '';
const roleOf = (value) => value === 'admin' ? 'Admin' : value === 'student' ? 'Student' : null;
const tableOf = (role) => role === 'Admin' ? 'users' : 'students';
const throttle = rateLimit({windowMs:15*60*1000,limit:15,standardHeaders:'draft-8',legacyHeaders:false,
  message:{error:'Too many recovery requests. Please try later.'}});
const sendMessage = 'If the email is registered, a recovery code will be sent.';
const noCache = (_req,res,next)=>{res.set('Cache-Control','no-store');next();};

async function setupRecoverySchema(pool) {
  await pool.query('ALTER TABLE students ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0');
  await pool.query(`CREATE TABLE IF NOT EXISTS password_recovery (
    role TEXT NOT NULL CHECK(role IN ('Student','Admin')),
    email TEXT NOT NULL,
    otp_hash TEXT,
    otp_expires_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    resend_after TIMESTAMPTZ,
    proof_hash TEXT,
    proof_expires_at TIMESTAMPTZ,
    PRIMARY KEY(role,email)
  )`);
}
function createRecoveryRouter({pool, transporter}) {
  if (!pool) throw new Error('PostgreSQL pool required');
  key();
  const mailer = transporter || nodemailer.createTransport({
    host:'smtp.gmail.com',port:465,secure:true,
    auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_APP_PASSWORD},
    tls:{rejectUnauthorized:true}
  });
  const router=express.Router();
  router.use(express.json({limit:'8kb'}),noCache,throttle);
  router.post('/forgot-password',async(req,res)=>{
    const role=roleOf(req.body?.role), email=normalize(req.body?.email);
    if(!role||email.length>254||!emailPattern.test(email))return res.status(400).json({error:'Valid role and email required'});
    let client;
    try{
      client=await pool.connect();
      await client.query('BEGIN');
      const account=await client.query(`SELECT email FROM ${tableOf(role)} WHERE LOWER(email)=$1 LIMIT 1`,[email]);
      if(account.rowCount!==1){await client.query('COMMIT');return res.json({message:sendMessage});}
      // Lock per account even on first request to serialize initial concurrent requests.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))',[role,email]);
      const current=await client.query('SELECT resend_after FROM password_recovery WHERE role=$1 AND email=$2 FOR UPDATE',[role,email]);
      if(current.rowCount && current.rows[0].resend_after && new Date(current.rows[0].resend_after).getTime()>Date.now()){
        await client.query('COMMIT');return res.json({message:sendMessage});
      }
      const otp=crypto.randomInt(0,1000000).toString().padStart(6,'0');
      const digest=hash('otp',role,email,otp);
      await client.query(`INSERT INTO password_recovery(role,email,otp_hash,otp_expires_at,attempts,resend_after,proof_hash,proof_expires_at)
        VALUES($1,$2,$3,NOW()+INTERVAL '5 minutes',0,NOW()+INTERVAL '60 seconds',NULL,NULL)
        ON CONFLICT(role,email) DO UPDATE SET otp_hash=EXCLUDED.otp_hash,otp_expires_at=EXCLUDED.otp_expires_at,
        attempts=0,resend_after=EXCLUDED.resend_after,proof_hash=NULL,proof_expires_at=NULL`,[role,email,digest]);
      // Holding row lock while sending ensures we don't issue an OTP that is immediately replaced.
      await mailer.sendMail({from:process.env.SMTP_FROM||process.env.SMTP_USER,to:email,
        subject:'PSNA Feedback password recovery code',
        text:`Your PSNA Feedback recovery code is ${otp}. It expires in 5 minutes. If you did not request this, ignore this message.`});
      await client.query('COMMIT');
      return res.json({message:sendMessage});
    }catch(err){
      if(client)await client.query('ROLLBACK').catch(()=>{});
      console.error('Password recovery request failed:',err?.code||err?.message);
      return res.status(503).json({error:'Recovery is temporarily unavailable'});
    }finally{client?.release();}
  });
  router.post('/verify-otp',async(req,res)=>{
    const role=roleOf(req.body?.role),email=normalize(req.body?.email),otp=req.body?.otp;
    if(!role||!emailPattern.test(email)||email.length>254||typeof otp!=='string'||!/^[0-9]{6}$/.test(otp))return res.status(400).json({error:'Invalid recovery details'});
    let client;
    try{
      client=await pool.connect();await client.query('BEGIN');
      const r=await client.query('SELECT * FROM password_recovery WHERE role=$1 AND email=$2 FOR UPDATE',[role,email]);
      const row=r.rows[0];
      if(!row||!row.otp_hash||!row.otp_expires_at||new Date(row.otp_expires_at).getTime()<=Date.now()||row.attempts>=MAX_ATTEMPTS){
        await client.query('COMMIT');return res.status(400).json({error:'Invalid or expired recovery code'});
      }
      const valid=crypto.timingSafeEqual(Buffer.from(hash('otp',role,email,otp),'hex'),Buffer.from(row.otp_hash,'hex'));
      if(!valid){
        await client.query('UPDATE password_recovery SET attempts=attempts+1 WHERE role=$1 AND email=$2',[role,email]);
        await client.query('COMMIT');return res.status(400).json({error:'Invalid or expired recovery code'});
      }
      const proof=crypto.randomBytes(32).toString('hex');
      await client.query(`UPDATE password_recovery SET otp_hash=NULL,otp_expires_at=NULL,
        proof_hash=$3,proof_expires_at=NOW()+INTERVAL '5 minutes'
        WHERE role=$1 AND email=$2`,[role,email,hash('proof',role,email,proof)]);
      await client.query('COMMIT');
      return res.json({resetToken:proof,expiresInSeconds:300});
    }catch(err){if(client)await client.query('ROLLBACK').catch(()=>{});console.error('OTP verification error:',err?.code||err?.message);return res.status(503).json({error:'Recovery is temporarily unavailable'});}
    finally{client?.release();}
  });
  router.post('/reset-password',async(req,res)=>{
    const role=roleOf(req.body?.role),email=normalize(req.body?.email),proof=req.body?.resetToken,password=req.body?.newPassword;
    if(!role||!emailPattern.test(email)||email.length>254||typeof proof!=='string'||!/^[a-f0-9]{64}$/.test(proof)||
       typeof password!=='string'||password.length<12||Buffer.byteLength(password,'utf8')>72)
      return res.status(400).json({error:'Valid reset token and password (12-72 UTF-8 bytes) required'});
    // Hash before acquiring DB lock to avoid long lock time.
    const passwordHash=await bcrypt.hash(password,12);
    let client;
    try{
      client=await pool.connect();await client.query('BEGIN');
      const r=await client.query('SELECT proof_hash,proof_expires_at FROM password_recovery WHERE role=$1 AND email=$2 FOR UPDATE',[role,email]);
      const row=r.rows[0];
      const digest=hash('proof',role,email,proof);
      if(!row?.proof_hash||!row.proof_expires_at||new Date(row.proof_expires_at).getTime()<=Date.now()||
        !crypto.timingSafeEqual(Buffer.from(digest,'hex'),Buffer.from(row.proof_hash,'hex'))){
        await client.query('COMMIT');return res.status(400).json({error:'Invalid or expired reset token'});
      }
      const updated=await client.query(`UPDATE ${tableOf(role)} SET password=$1,session_version=session_version+1
        WHERE LOWER(email)=$2 RETURNING email`,[passwordHash,email]);
      if(updated.rowCount!==1)throw new Error('Account not found or ambiguous');
      await client.query('DELETE FROM password_recovery WHERE role=$1 AND email=$2',[role,email]);
      await client.query('COMMIT');
      return res.json({success:true,message:'Password reset. Please sign in again.'});
    }catch(err){if(client)await client.query('ROLLBACK').catch(()=>{});console.error('Password reset error:',err?.code||err?.message);return res.status(503).json({error:'Recovery is temporarily unavailable'});}
    finally{client?.release();}
  });
  return router;
}
module.exports={createRecoveryRouter,setupRecoverySchema};
