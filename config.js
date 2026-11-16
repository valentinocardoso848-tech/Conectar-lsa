/* ============================================================
   CONFIGURACIÓN DE CONECT.AR CON LSA
   Este es el ÚNICO archivo que hay que tocar para conectar la
   app con el servidor. No hace falta tocar index.html.
   ============================================================ */
window.CONECTAR_CONFIG = {

  /* Dirección del servidor de Render, tal cual te la da Render,
     entre comillas y SIN barra al final.
     Ejemplo: "https://conectar-lsa-servidor.onrender.com"      */
  servidor: "",

  /* EmailJS: manda el código de verificación al crear el perfil.
     Si estos datos dejan de andar, borralos (dejá "") y el perfil
     se crea sin verificar el mail.                              */
  emailjsPublicKey: "jtCrfSwF1TxBJCD0i",
  emailjsServiceId: "service_skf8aqp",
  emailjsTemplateId: "template_jrwxfhg"
};
