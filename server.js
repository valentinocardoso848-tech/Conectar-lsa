/* ============================================================
   SERVIDOR DE CONECT.AR CON LSA
   ------------------------------------------------------------
   Guarda perfiles, puntos, cupones y canjes en Firebase
   (Firestore). La app NUNCA toca la base de datos directo:
   todo pasa por acá, que es donde se controla quién puede hacer qué.

   Variables que hay que cargar en Render (Environment):
     FIREBASE_SERVICE_ACCOUNT  el contenido del .json que bajaste de Firebase
     ADMIN_USUARIO             el usuario del panel de administrador
     ADMIN_CLAVE               la clave del panel de administrador
     TOKEN_SECRETO             cualquier texto largo y al azar (Render lo genera)
     ORIGEN_PERMITIDO          (opcional) https://TU-USUARIO.github.io
   ============================================================ */
"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");

/* ---------- conexión con Firebase ---------- */
function leerCuentaDeServicio() {
  const crudo = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!crudo) {
    console.error("FALTA la variable FIREBASE_SERVICE_ACCOUNT en Render (Environment).");
    process.exit(1);
  }
  let cuenta;
  try {
    cuenta = JSON.parse(crudo);
  } catch (e) {
    console.error("FIREBASE_SERVICE_ACCOUNT no es un JSON válido. Pegá el contenido COMPLETO del archivo, desde la primera { hasta la última }.");
    process.exit(1);
  }
  if (cuenta.private_key) cuenta.private_key = cuenta.private_key.replace(/\\n/g, "\n");
  return cuenta;
}
admin.initializeApp({ credential: admin.credential.cert(leerCuentaDeServicio()) });
const db = admin.firestore();

/* ---------- reglas del juego ---------- */
const PUNTOS_POR_SENA = 3;
const ESPERA_ENTRE_PUNTOS_MS = 15 * 1000;   // una grabación dura 7 s: menos de 15 s entre una y otra es sospechoso
const MAX_PUNTOS_POR_DIA = 90;              // 30 señas por día
const DURACION_SESION_ADMIN_MS = 8 * 60 * 60 * 1000;

const ADMIN_USUARIO = process.env.ADMIN_USUARIO || "";
const ADMIN_CLAVE = process.env.ADMIN_CLAVE || "";
const TOKEN_SECRETO = process.env.TOKEN_SECRETO || crypto.randomBytes(32).toString("hex");
const ORIGENES = (process.env.ORIGEN_PERMITIDO || "")
  .split(",").map(function (s) { return s.trim().replace(/\/+$/, ""); }).filter(Boolean);

/* ---------- utilidades ---------- */
function hash(t) { return crypto.createHash("sha256").update(String(t)).digest("hex"); }
function igualSeguro(a, b) {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}
function texto(v, max) {
  if (typeof v !== "string") return "";
  return v.replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, max);
}
function hoy() { return new Date().toISOString().slice(0, 10); }

/* límite de pedidos por IP, en memoria (alcanza para un proyecto de este tamaño) */
const contadores = new Map();
function superaLimite(clave, max, ventanaMs) {
  const ahora = Date.now();
  let r = contadores.get(clave);
  if (!r || ahora > r.fin) { r = { n: 0, fin: ahora + ventanaMs }; contadores.set(clave, r); }
  r.n++;
  return r.n > max;
}
setInterval(function () {
  const ahora = Date.now();
  for (const [k, v] of contadores) if (ahora > v.fin) contadores.delete(k);
}, 60 * 1000).unref();

function limitar(nombre, max, ventanaMs) {
  return function (req, res, next) {
    if (superaLimite(nombre + ":" + req.ip, max, ventanaMs)) {
      return res.status(429).json({ error: "Demasiados intentos seguidos. Esperá un rato y probá de nuevo." });
    }
    next();
  };
}

/* envuelve funciones async para que un error no tumbe el servidor */
function seguro(fn) {
  return function (req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(function (e) {
      console.error(e);
      if (!res.headersSent) res.status(500).json({ error: "Error del servidor. Probá de nuevo en un momento." });
    });
  };
}

/* El perfil se identifica con id + token secreto. El token se le da a
   la app UNA vez, al crear el perfil, y acá solo se guarda su hash. */
async function perfilAutorizado(body) {
  const id = body && body.perfilId, token = body && body.token;
  if (typeof id !== "string" || !/^[A-Za-z0-9_-]{10,64}$/.test(id)) return null;
  if (typeof token !== "string" || token.length < 20 || token.length > 200) return null;
  const ref = db.collection("perfiles").doc(id);
  const snap = await ref.get();
  if (!snap.exists) return null;
  const d = snap.data();
  if (!d.tokenHash || !igualSeguro(d.tokenHash, hash(token))) return null;
  return { ref: ref, datos: d };
}

/* sesión de administrador: un texto firmado que vence solo */
function firmarSesion(datos) {
  const cuerpo = Buffer.from(JSON.stringify(datos)).toString("base64url");
  const firma = crypto.createHmac("sha256", TOKEN_SECRETO).update(cuerpo).digest("base64url");
  return cuerpo + "." + firma;
}
function soloAdmin(req, res, next) {
  const h = req.get("authorization") || "";
  const t = h.indexOf("Bearer ") === 0 ? h.slice(7) : "";
  const partes = t.split(".");
  const noAutorizado = function (msg) { res.status(401).json({ error: msg || "Iniciá sesión de nuevo." }); };
  if (partes.length !== 2) return noAutorizado();
  const esperada = crypto.createHmac("sha256", TOKEN_SECRETO).update(partes[0]).digest("base64url");
  if (!igualSeguro(partes[1], esperada)) return noAutorizado();
  let datos;
  try { datos = JSON.parse(Buffer.from(partes[0], "base64url").toString("utf8")); } catch (e) { return noAutorizado(); }
  if (!datos || !datos.vence || Date.now() > datos.vence) return noAutorizado("La sesión venció. Entrá de nuevo.");
  next();
}

/* ---------- la app web ---------- */
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: ORIGENES.length ? ORIGENES : true }));
app.use(express.json({ limit: "20kb" }));

/* para ver que el servidor está vivo (y para "despertarlo") */
app.get("/", function (req, res) {
  res.json({ ok: true, servicio: "Conect.AR con LSA", hora: new Date().toISOString() });
});

/* ===== PERFILES ===== */
app.post("/perfiles", limitar("perfiles", 10, 60 * 60 * 1000), seguro(async function (req, res) {
  const nombre = texto(req.body.nombre, 40);
  const apellido = texto(req.body.apellido, 40);
  const email = texto(req.body.email, 100).toLowerCase();
  if (!nombre || !apellido) return res.status(400).json({ error: "Faltan el nombre o el apellido." });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Ese correo no parece válido." });

  const id = crypto.randomUUID();
  const token = crypto.randomBytes(24).toString("base64url");
  await db.collection("perfiles").doc(id).set({
    nombre: nombre, apellido: apellido, email: email,
    puntos: 0, puntosHoy: 0, diaPuntos: "", ultimoPunto: 0,
    tokenHash: hash(token),
    creado: new Date().toISOString()
  });
  res.json({ id: id, token: token, puntos: 0 });
}));

/* los puntos y canjes de MI perfil */
app.post("/perfiles/mis-datos", limitar("misdatos", 60, 60 * 1000), seguro(async function (req, res) {
  const p = await perfilAutorizado(req.body);
  if (!p) return res.status(401).json({ error: "Perfil no reconocido." });
  const snap = await db.collection("canjes").where("perfilId", "==", p.ref.id).get();
  const canjes = [];
  snap.forEach(function (d) { const c = d.data(); canjes.push({ nombre: c.nombre, costo: c.costo, fecha: c.fecha }); });
  canjes.sort(function (a, b) { return String(b.fecha).localeCompare(String(a.fecha)); });
  res.json({ puntos: p.datos.puntos || 0, canjes: canjes });
}));

/* borrar mi perfil (y mis canjes) */
app.post("/perfiles/borrar", limitar("borrar", 10, 60 * 60 * 1000), seguro(async function (req, res) {
  const p = await perfilAutorizado(req.body);
  if (!p) return res.status(401).json({ error: "Perfil no reconocido." });
  const canjes = await db.collection("canjes").where("perfilId", "==", p.ref.id).get();
  const lote = db.batch();
  canjes.forEach(function (d) { lote.delete(d.ref); });
  lote.delete(p.ref);
  await lote.commit();
  res.json({ ok: true });
}));

/* ===== PUNTOS ===== */
app.post("/puntos/otorgar", limitar("puntos", 30, 60 * 1000), seguro(async function (req, res) {
  const p = await perfilAutorizado(req.body);
  if (!p) return res.status(401).json({ error: "Perfil no reconocido." });

  const resultado = await db.runTransaction(async function (t) {
    const snap = await t.get(p.ref);
    const d = snap.data();
    const ahora = Date.now();
    const dia = hoy();
    const puntosHoy = d.diaPuntos === dia ? (d.puntosHoy || 0) : 0;
    if (ahora - (d.ultimoPunto || 0) < ESPERA_ENTRE_PUNTOS_MS) {
      return { estado: 429, cuerpo: { error: "Muy rápido: esperá unos segundos entre grabación y grabación.", puntos: d.puntos || 0 } };
    }
    if (puntosHoy + PUNTOS_POR_SENA > MAX_PUNTOS_POR_DIA) {
      return { estado: 429, cuerpo: { error: "Llegaste al máximo de puntos de hoy. ¡Mañana seguís sumando!", puntos: d.puntos || 0 } };
    }
    const nuevos = (d.puntos || 0) + PUNTOS_POR_SENA;
    t.update(p.ref, { puntos: nuevos, puntosHoy: puntosHoy + PUNTOS_POR_SENA, diaPuntos: dia, ultimoPunto: ahora });
    return { estado: 200, cuerpo: { puntos: nuevos } };
  });
  res.status(resultado.estado).json(resultado.cuerpo);
}));

/* ===== CUPONES ===== */
app.get("/cupones", seguro(async function (req, res) {
  const snap = await db.collection("cupones").get();
  const lista = [];
  snap.forEach(function (d) { const c = d.data(); lista.push({ id: d.id, nombre: c.nombre, costo: c.costo }); });
  lista.sort(function (a, b) { return a.costo - b.costo; });
  res.json(lista);
}));

app.post("/cupones/canjear", limitar("canjear", 20, 60 * 1000), seguro(async function (req, res) {
  const p = await perfilAutorizado(req.body);
  if (!p) return res.status(401).json({ error: "Perfil no reconocido." });
  const cuponId = texto(req.body.cuponId, 64);
  if (!cuponId || cuponId.indexOf("/") !== -1) return res.status(400).json({ error: "Cupón inválido." });

  const cuponRef = db.collection("cupones").doc(cuponId);
  const resultado = await db.runTransaction(async function (t) {
    const perfilSnap = await t.get(p.ref);
    const cuponSnap = await t.get(cuponRef);
    if (!cuponSnap.exists) return { estado: 404, cuerpo: { error: "Ese cupón ya no existe." } };
    const perfil = perfilSnap.data(), cupon = cuponSnap.data();
    const puntos = perfil.puntos || 0;
    if (puntos < cupon.costo) return { estado: 400, cuerpo: { error: "No te alcanzan los puntos.", puntos: puntos } };
    const quedan = puntos - cupon.costo;
    t.update(p.ref, { puntos: quedan });
    t.set(db.collection("canjes").doc(), {
      perfilId: p.ref.id,
      perfilNombre: perfil.nombre + " " + perfil.apellido,
      cuponId: cuponId, nombre: cupon.nombre, costo: cupon.costo,
      fecha: new Date().toISOString()
    });
    return { estado: 200, cuerpo: { puntos: quedan } };
  });
  res.status(resultado.estado).json(resultado.cuerpo);
}));

/* ===== ADMINISTRADOR ===== */
app.post("/admin/login", limitar("login", 8, 15 * 60 * 1000), function (req, res) {
  if (!ADMIN_USUARIO || !ADMIN_CLAVE) {
    return res.status(503).json({ error: "El servidor no tiene cargados ADMIN_USUARIO y ADMIN_CLAVE (en Render → Environment)." });
  }
  const usuario = typeof req.body.usuario === "string" ? req.body.usuario.trim() : "";
  const clave = typeof req.body.clave === "string" ? req.body.clave : "";
  const ok = igualSeguro(hash(usuario), hash(ADMIN_USUARIO)) && igualSeguro(hash(clave), hash(ADMIN_CLAVE));
  if (!ok) return res.status(401).json({ error: "Usuario o clave incorrectos." });
  res.json({ token: firmarSesion({ rol: "admin", vence: Date.now() + DURACION_SESION_ADMIN_MS }) });
});

app.get("/admin/resumen", soloAdmin, seguro(async function (req, res) {
  const [perfilesSnap, canjesSnap, cuponesSnap] = await Promise.all([
    db.collection("perfiles").get(),
    db.collection("canjes").get(),
    db.collection("cupones").get()
  ]);
  const perfiles = [], canjes = [], cupones = [];
  perfilesSnap.forEach(function (d) { const p = d.data(); perfiles.push({ nombre: p.nombre, apellido: p.apellido, puntos: p.puntos || 0 }); });
  canjesSnap.forEach(function (d) { const c = d.data(); canjes.push({ perfilNombre: c.perfilNombre, nombre: c.nombre, costo: c.costo, fecha: c.fecha }); });
  cuponesSnap.forEach(function (d) { const c = d.data(); cupones.push({ id: d.id, nombre: c.nombre, costo: c.costo }); });
  perfiles.sort(function (a, b) { return b.puntos - a.puntos; });
  canjes.sort(function (a, b) { return String(b.fecha).localeCompare(String(a.fecha)); });
  cupones.sort(function (a, b) { return a.costo - b.costo; });
  res.json({ perfiles: perfiles, canjes: canjes, cupones: cupones });
}));

app.post("/admin/cupones", soloAdmin, seguro(async function (req, res) {
  const nombre = texto(req.body.nombre, 80);
  const costo = Number(req.body.costo);
  if (!nombre) return res.status(400).json({ error: "Falta el nombre del cupón." });
  if (!Number.isInteger(costo) || costo < 1 || costo > 100000) return res.status(400).json({ error: "El costo tiene que ser un número entero entre 1 y 100000." });
  const ref = await db.collection("cupones").add({ nombre: nombre, costo: costo, creado: new Date().toISOString() });
  res.json({ id: ref.id });
}));

app.delete("/admin/cupones/:id", soloAdmin, seguro(async function (req, res) {
  const id = texto(req.params.id, 64);
  if (!id) return res.status(400).json({ error: "Cupón inválido." });
  await db.collection("cupones").doc(id).delete();
  res.json({ ok: true });
}));

app.use(function (req, res) { res.status(404).json({ error: "No existe esa dirección." }); });

const PUERTO = process.env.PORT || 3000;
app.listen(PUERTO, function () {
  console.log("Servidor de Conect.AR con LSA escuchando en el puerto " + PUERTO);
  if (!ADMIN_USUARIO || !ADMIN_CLAVE) console.warn("Ojo: faltan ADMIN_USUARIO / ADMIN_CLAVE, el panel de administrador no va a funcionar.");
  if (!process.env.TOKEN_SECRETO) console.warn("Ojo: falta TOKEN_SECRETO; las sesiones de administrador se cortan cada vez que el servidor se reinicia.");
});
