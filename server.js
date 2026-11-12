const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const root = __dirname;
const dataDir = path.join(root, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(process.env.DATABASE_PATH || path.join(dataDir, 'credvault.sqlite'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS applications (
    applicationId TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL,
    gender TEXT NOT NULL, city TEXT NOT NULL, state TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('Pending','Approved','Rejected')),
    submittedAt TEXT NOT NULL, rejectionReason TEXT
  );
  CREATE TABLE IF NOT EXISTS certificates (
    certificateId TEXT PRIMARY KEY, applicationId TEXT NOT NULL UNIQUE REFERENCES applications(applicationId),
    issuedOn TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('Valid','Revoked'))
  );
  CREATE TABLE IF NOT EXISTS admins (
    username TEXT PRIMARY KEY, passwordHash TEXT NOT NULL, salt TEXT NOT NULL
  );
`);

const adminName = process.env.ADMIN_USERNAME || 'admin';
if (!db.prepare('SELECT 1 FROM admins WHERE username = ?').get(adminName)) {
  const salt = crypto.randomBytes(16).toString('hex');
  const password = process.env.ADMIN_PASSWORD || 'admin';
  const hash = crypto.pbkdf2Sync(password, salt, 210000, 32, 'sha256').toString('hex');
  db.prepare('INSERT INTO admins(username,passwordHash,salt) VALUES(?,?,?)').run(adminName, hash, salt);
  if (!process.env.ADMIN_PASSWORD) console.warn('Using development admin password. Set ADMIN_USERNAME and ADMIN_PASSWORD before deployment.');
}

const secret = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const mime = { '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml' };
const json = (res, code, body) => { res.writeHead(code, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store' }); res.end(JSON.stringify(body)); };
const notFound = (res, what='Resource') => json(res,404,{success:false,message:`${what} not found.`});
const bad = (res, message) => json(res,400,{success:false,message});
const fail = (res, error) => json(res,500,{success:false,message:'An internal server error occurred.'});
function readBody(req) {
  return new Promise((resolve,reject)=>{ let raw=''; req.on('data', chunk=>{ raw+=chunk; if(raw.length>16_384) reject(new Error('Request body too large')); }); req.on('end',()=>{ try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Invalid JSON body')); } }); req.on('error',reject); });
}
function token(username) {
  const payload=Buffer.from(JSON.stringify({sub:username,exp:Date.now()+8*60*60*1000})).toString('base64url');
  const sig=crypto.createHmac('sha256',secret).update(payload).digest('base64url'); return `${payload}.${sig}`;
}
function authorized(req) {
  const match=(req.headers.authorization||'').match(/^Bearer (.+)$/); if(!match)return false;
  const [payload,sig]=match[1].split('.'); if(!payload||!sig)return false;
  const expected=crypto.createHmac('sha256',secret).update(payload).digest(); let actual;
  try { actual=Buffer.from(sig,'base64url'); } catch { return false; }
  if(actual.length!==expected.length||!crypto.timingSafeEqual(actual,expected))return false;
  try { const data=JSON.parse(Buffer.from(payload,'base64url').toString()); return data.exp>Date.now()&&!!db.prepare('SELECT 1 FROM admins WHERE username=?').get(data.sub); } catch { return false; }
}
const appSelect = 'SELECT applicationId,name,phone,gender,city,state,status,submittedAt,rejectionReason FROM applications';
const certSelect = 'SELECT c.certificateId,c.applicationId,a.name,a.phone,a.city,a.state,c.issuedOn,c.status FROM certificates c JOIN applications a USING(applicationId)';
const randomId = prefix => `${prefix}-${crypto.randomUUID().replaceAll('-','').slice(0,12).toUpperCase()}`;
function validateApplication(b) {
  const fields=['name','phone','gender','city','state'];
  for(const key of fields)if(typeof b[key]!=='string'||!b[key].trim())return `${key} is required.`;
  if(b.name.trim().length>120||b.city.trim().length>100||b.state.trim().length>100)return 'Name, city, or state is too long.';
  if(!/^[0-9+() -]{7,20}$/.test(b.phone.trim()))return 'Phone must contain 7–20 digits or common phone punctuation.';
  if(!['Male','Female','Other'].includes(b.gender.trim()))return 'Gender must be Male, Female, or Other.';
  return null;
}
async function handleApi(req,res,url) {
  const p=url.pathname, method=req.method;
  if(method==='POST'&&p==='/api/applications'){
    let b;try{b=await readBody(req)}catch(e){return bad(res,e.message)}
    const issue=validateApplication(b);if(issue)return bad(res,issue);
    const id=randomId('APP'), submittedAt=new Date().toISOString();
    db.prepare('INSERT INTO applications(applicationId,name,phone,gender,city,state,status,submittedAt) VALUES(?,?,?,?,?,?,?,?)').run(id,b.name.trim(),b.phone.trim(),b.gender.trim(),b.city.trim(),b.state.trim(),'Pending',submittedAt);
    return json(res,201,{success:true,message:'Application submitted successfully.',applicationId:id,status:'Pending'});
  }
  let m=p.match(/^\/api\/applications\/track\/([^/]+)$/);
  if(method==='GET'&&m){const a=db.prepare('SELECT applicationId,name,status,submittedAt FROM applications WHERE applicationId=?').get(decodeURIComponent(m[1]));return a?json(res,200,a):notFound(res,'Application');}
  m=p.match(/^\/api\/certificates\/verify\/([^/]+)$/);
  if(method==='GET'&&m){const c=db.prepare(`${certSelect} WHERE c.certificateId=?`).get(decodeURIComponent(m[1]));if(!c)return notFound(res,'Certificate');const {certificateId,name,phone,issuedOn,status}=c;return json(res,200,{certificateId,name,phone,issuedOn,status});}
  if(method==='POST'&&p==='/api/admin/login'){
    let b;try{b=await readBody(req)}catch(e){return bad(res,e.message)}
    if(typeof b.username!=='string'||typeof b.password!=='string')return bad(res,'Username and password are required.');
    const a=db.prepare('SELECT * FROM admins WHERE username=?').get(b.username);
    const hash=a?crypto.pbkdf2Sync(b.password,a.salt,210000,32,'sha256'):Buffer.alloc(32);
    const valid=!!a&&crypto.timingSafeEqual(hash,Buffer.from(a.passwordHash,'hex'));
    return valid?json(res,200,{success:true,message:'Login successful.',token:token(a.username)}):json(res,401,{success:false,message:'Invalid username or password.'});
  }
  if(p.startsWith('/api/admin/')){
    if(!authorized(req))return json(res,401,{success:false,message:'Admin authentication required.'});
    if(method==='GET'&&p==='/api/admin/applications')return json(res,200,db.prepare(`${appSelect} ORDER BY submittedAt DESC`).all());
    if(method==='GET'&&p==='/api/admin/certificates')return json(res,200,db.prepare(`${certSelect} ORDER BY issuedOn DESC`).all());
    m=p.match(/^\/api\/admin\/applications\/([^/]+)\/(approve|reject)$/);
    if(method==='PATCH'&&m){const id=decodeURIComponent(m[1]), action=m[2], a=db.prepare('SELECT * FROM applications WHERE applicationId=?').get(id);if(!a)return notFound(res,'Application');if(a.status!=='Pending')return json(res,409,{success:false,message:`Application is already ${a.status.toLowerCase()}.`});
      if(action==='approve'){const certificateId=randomId('CERT');const issue=db.prepare('INSERT INTO certificates(certificateId,applicationId,issuedOn,status) VALUES(?,?,?,?)');const update=db.prepare("UPDATE applications SET status='Approved' WHERE applicationId=?");db.exec('BEGIN IMMEDIATE');try{issue.run(certificateId,id,new Date().toISOString(),'Valid');update.run(id);db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}return json(res,200,{success:true,message:'Application approved.',applicationId:id,status:'Approved',certificateId});}
      let b={};try{b=await readBody(req)}catch(e){return bad(res,e.message)}const reason=typeof b.reason==='string'?b.reason.trim().slice(0,500):null;db.prepare("UPDATE applications SET status='Rejected',rejectionReason=? WHERE applicationId=?").run(reason,id);return json(res,200,{success:true,message:'Application rejected.',applicationId:id,status:'Rejected'});
    }
    m=p.match(/^\/api\/admin\/certificates\/([^/]+)\/revoke$/);
    if((method==='PATCH'||method==='GET')&&m){const id=decodeURIComponent(m[1]),c=db.prepare('SELECT * FROM certificates WHERE certificateId=?').get(id);if(!c)return notFound(res,'Certificate');if(c.status==='Revoked')return json(res,200,{success:true,message:'Certificate is already revoked.',certificateId:id,status:'Revoked'});db.prepare("UPDATE certificates SET status='Revoked' WHERE certificateId=?").run(id);return json(res,200,{success:true,message:'Certificate revoked.',certificateId:id,status:'Revoked'});}
  }
  return json(res,404,{success:false,message:'API endpoint not found.'});
}
const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://localhost');
  if(url.pathname.startsWith('/api/')){try{return await handleApi(req,res,url)}catch(e){console.error(e);return fail(res,e)}}
  if(req.method!=='GET'&&req.method!=='HEAD')return res.writeHead(405).end('Method not allowed.');
  const pathname=decodeURIComponent(url.pathname);
  const publicFiles=new Set(['/index.html','/app.js','/styles.css']);
  const isScreenshot=/^\/screenshots\/[a-z-]+\.svg$/.test(pathname);
  if(pathname==='/'||publicFiles.has(pathname)||isScreenshot){const candidate=path.resolve(root,`.${pathname}`);const file=fs.existsSync(candidate)&&fs.statSync(candidate).isFile()?candidate:path.join(root,'index.html');
  fs.readFile(file,(err,content)=>{if(err)return res.writeHead(500).end('Unable to read application files.');res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});res.end(content)});
  } else res.writeHead(404).end('Not found.');
});
const port=Number(process.env.PORT)||4173;
server.listen(port,'0.0.0.0',()=>console.log(`CredVault API and app running at http://localhost:${port}`));
function shutdown(){db.close();server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),3000).unref();}
process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
