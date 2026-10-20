import React,{useState} from 'react';
/** Mount from either login screen: <ForgotPassword role="student" onBack={...}/> */
export default function ForgotPassword({role,onBack,apiBase='/api/auth'}){
  const [stage,setStage]=useState(0),[email,setEmail]=useState(''),[otp,setOtp]=useState('');
  const [resetToken,setResetToken]=useState(''),[password,setPassword]=useState(''),[confirm,setConfirm]=useState('');
  const [message,setMessage]=useState(''),[busy,setBusy]=useState(false);
  async function submit(event){
    event.preventDefault();setMessage('');
    if(stage===2 && password!==confirm){setMessage('Passwords do not match');return;}
    setBusy(true);
    try{
      const endpoint=['forgot-password','verify-otp','reset-password'][stage];
      const payload=stage===0?{role,email}:stage===1?{role,email,otp}:{role,email,resetToken,newPassword:password};
      const res=await fetch(`${apiBase}/${endpoint}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),cache:'no-store'});
      const data=await res.json();
      if(!res.ok){setMessage(data.error||'Request failed');return;}
      if(stage===0){setStage(1);setMessage('If this address is registered, check your email for a six-digit code.');}
      else if(stage===1){setResetToken(data.resetToken);setStage(2);setMessage('Code verified. Choose a new password.');}
      else{setStage(3);setOtp('');setResetToken('');setPassword('');setConfirm('');setMessage('Password reset. Sign in with your new password.');}
    }catch{setMessage('Unable to connect. Please try again.');}finally{setBusy(false);}
  }
  return <div className="login-bg"><div className="login-card" style={{maxWidth:460,padding:32}}>
    <h2>{role==='admin'?'Admin':'Student'} password recovery</h2>
    {stage<3&&<form onSubmit={submit}>
      {stage===0&&<label>Registered email<input className="login-input" type="email" autoComplete="email" required value={email} onChange={e=>setEmail(e.target.value)} /></label>}
      {stage===1&&<label>Six-digit code<input className="login-input" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required value={otp} onChange={e=>setOtp(e.target.value)} /></label>}
      {stage===2&&<>
        <label>New password (minimum 12 characters)<input className="login-input" type="password" autoComplete="new-password" minLength={12} required value={password} onChange={e=>setPassword(e.target.value)}/></label>
        <label>Confirm password<input className="login-input" type="password" autoComplete="new-password" required value={confirm} onChange={e=>setConfirm(e.target.value)}/></label>
      </>}
      <button className="login-submit-btn" type="submit" disabled={busy}>{busy?'Please wait…':['Send recovery code','Verify code','Reset password'][stage]}</button>
    </form>}
    <p role="status">{message}</p>
    {stage===1&&<button type="button" disabled={busy} onClick={()=>{setStage(0);setOtp('');setMessage('');}}>Request another code (60-second cooldown)</button>}
    <button type="button" onClick={onBack}>Back to login</button>
  </div></div>;
}
