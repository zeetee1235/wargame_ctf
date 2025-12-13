function b64uDecBytes(s){
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function xorRepeat(data, key){
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++)
    out[i] = data[i] ^ key[i % key.length];
  return out;
}

function sha256Bytes(str){
  const arr = sha256.array(str);
  return new Uint8Array(arr);
}

const logEl = document.getElementById('log');
const term  = document.getElementById('term');

function printLine(s = "", cls = ""){
  const d = document.createElement('div');
  if (cls) d.className = cls;
  d.textContent = s;
  logEl.appendChild(d);
  term.scrollTop = term.scrollHeight;
}

async function typeLine(s, cls = "", speed = 12){
  return new Promise(res => {
    const d = document.createElement('div');
    if (cls) d.className = cls;
    logEl.appendChild(d);
    let i = 0;
    (function tick(){
      d.textContent = s.slice(0, i) + (i < s.length ? "█" : "");
      i++;
      term.scrollTop = term.scrollHeight;
      if (i <= s.length) setTimeout(tick, speed);
      else { d.textContent = s; res(); }
    })();
  });
}

function showHelp(){
  printLine("$ help");
  printLine("  commands:");
  printLine("    get       - fetch sample user token");
  printLine("    redeem T  - POST token T to /redeem");
  printLine("    clear     - clear screen");
  printLine("    about     - show service info");
  printLine("    help      - show this help");
  printLine("    (tip: ↑/↓ history, Ctrl+L clear, Ctrl+G get)");
}

let currentCE = null;
const history = [];
let hIdx = -1;

function placeCaretEnd(el){
  const r = document.createRange();
  r.selectNodeContents(el);
  r.collapse(false);
  const s = window.getSelection();
  s.removeAllRanges();
  s.addRange(r);
}

function newPrompt(prefill = ""){
  const wrap = document.createElement('div');
  wrap.className = 'promptline';
  wrap.innerHTML = `<span class="ps1">$</span><span class="ce" id="ce" contenteditable="true" spellcheck="false"></span>`;
  logEl.appendChild(wrap);
  currentCE = wrap.querySelector('#ce');

  wrap.addEventListener('mousedown', (e) => {
    if (document.activeElement !== currentCE){
      e.preventDefault();
      currentCE.focus();
      placeCaretEnd(currentCE);
    }
  });

  if (prefill) currentCE.textContent = prefill;
  placeCaretEnd(currentCE);
  term.scrollTop = term.scrollHeight;

  currentCE.addEventListener('keydown', onCEKeydown);
  currentCE.focus();
}

function normalizeInput(text){
  return (text || "").replace(/\u00a0/g, ' ').trim();
}

function onCEKeydown(e){
  if (e.key === "ArrowUp"){
    if (history.length && hIdx < history.length - 1){
      hIdx++;
      currentCE.textContent = history[history.length - 1 - hIdx];
      placeCaretEnd(currentCE);
      e.preventDefault();
    }
    return;
  }
  if (e.key === "ArrowDown"){
    if (hIdx > 0){
      hIdx--;
      currentCE.textContent = history[history.length - 1 - hIdx];
      placeCaretEnd(currentCE);
      e.preventDefault();
      return;
    }
    if (hIdx === 0){
      hIdx = -1;
      currentCE.textContent = "";
      e.preventDefault();
      return;
    }
  }

  if (e.key === "Enter" && !e.shiftKey){
    e.preventDefault();
    const line = normalizeInput(currentCE.textContent);


    const parent = currentCE.parentElement;
    parent.innerHTML = "";
    const ps1 = document.createElement('span');
    ps1.className = 'ps1';
    ps1.textContent = '$';
    parent.appendChild(ps1);
    if (line) parent.appendChild(document.createTextNode(' ' + line));

    run(line);
  }
}

// 글로벌 단축키
window.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key.toLowerCase() === "l"){
    e.preventDefault();

    run("clear");
  }
  if (e.ctrlKey && e.key.toLowerCase() === "g"){
    e.preventDefault();
    cmdGet();
  }
});

// ===== commands =====
async function cmdGet(){
  try{
    const r = await fetch("/sample_user", { cache: "no-store" });
    if (!r.ok){
      printLine("SERVICE ERROR", "err");
      return;
    }
    const j = await r.json();
    if (!j.token || typeof j.token !== "string"){
      printLine("SERVICE ERROR", "err");
      return;
    }
    await typeLine("sample_token = " + j.token);
  }catch(e){
    printLine("SERVICE ERROR", "err");
  }
}

async function cmdRedeem(token){
  if (!token){
    printLine("No Input", "err");
    return;
  }
  try{
    const r = await fetch("/redeem", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    const j = await r.json();
    if (!(r.ok && j.ok)){
      printLine("ACCESS DENIED", "err");
      return;
    }

    
    const key = sha256Bytes(token);      
    const cap = b64uDecBytes(j.capsule);
    const dec = xorRepeat(cap, key);
    const flag = new TextDecoder().decode(dec);
    await typeLine("ACCESS GRANTED", "ok", 18);
    await typeLine("flag => " + flag, "ok", 10);
  }catch(e){
    printLine("ERROR OCCURED WHILE DECRYPTING CAPSULE", "err");
  }
}

function cmdClear(){
  logEl.innerHTML = "";
  showHelp();
}

function cmdAbout(){
  printLine("Ticket Redeemer (CRT mode)");
  printLine("Endpoints:");
  printLine("  GET  /sample_user");
  printLine('  POST /redeem {"token":"..."}');
}

// dispatcher
async function run(line){
  if (line.length){
    history.push(line);
    hIdx = -1;
  }
  const [cmd, ...rest] = line.split(/\s+/);
  const argStr = rest.join(" ");
  switch ((cmd || "").toLowerCase()){
    case "":
      break;
    case "help":
      showHelp();
      break;
    case "about":
      cmdAbout();
      break;
    case "clear":
      cmdClear();
      break;
    case "get":
      await cmdGet();
      break;
    case "redeem":
      await cmdRedeem(normalizeInput(argStr));
      break;
    default:
      printLine("Invalid command", "err");
  }
  newPrompt(); 
}

newPrompt();
term.focus();

