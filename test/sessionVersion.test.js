'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {checkSessionVersion,getSessionVersion}=require('../src/sessionVersion');
test('rejects tokens without a version',async()=>{
  assert.equal(await checkSessionVersion({query:()=>{throw Error('should not query')}},{role:'Student',email:'x@example.com'}),false);
});
test('rejects old JWT version after reset',async()=>{
  const pool={query:async()=>({rowCount:1,rows:[{session_version:2}]})};
  assert.equal(await checkSessionVersion(pool,{role:'Student',email:'x@example.com',sessionVersion:1}),false);
  assert.equal(await checkSessionVersion(pool,{role:'Student',email:'x@example.com',sessionVersion:2}),true);
  assert.equal(await getSessionVersion(pool,'Student','x@example.com'),2);
});
test('rejects missing account',async()=>{
  assert.equal(await checkSessionVersion({query:async()=>({rowCount:0,rows:[]})},{role:'Admin',email:'x@example.com',sessionVersion:0}),false);
});
