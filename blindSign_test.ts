import { generateKeyPair, blind, blindSign, unblind, blindVerify } from "./rsa.js";
import { gcd, modPow } from "bigint-crypto-utils";

// ---------- Utilidades de impresión ----------
function section(n: number, title: string) {
  console.log(`\n── ${n}. ${title} ` + "─".repeat(Math.max(2, 56 - title.length)));
}
function show(label: string, value: bigint | string | number | boolean) {
  console.log(`   ${label.padEnd(26)} = ${value}`);
}
function check(cond: boolean, msg: string) {
  console.log(`   ${cond ? "✓ OK   " : "✗ FALLO"} ${msg}`);
  if (!cond) process.exitCode = 1;
}
const bits = (x: bigint) => x.toString(2).length;

// ---------- Claves ----------
console.log("════════════════════════════════════════════════════════════");
console.log("  TEST DE FIRMA A CIEGAS RSA (sin servidores ni base de datos)");
console.log("════════════════════════════════════════════════════════════");

console.log("\nGenerando par de claves (512 bits, solo para que el test sea rápido)...");
const { publicKey, privateKey } = generateKeyPair(512);
show("n (módulo)", publicKey.n);
show("n (bits)", bits(publicKey.n));
show("e (exponente público)", publicKey.e);
show("d (exponente privado)", privateKey.d + "   ← secreto, aquí se muestra solo para el demo");

// ---------- 1. Round-trip ----------
section(1, "Round-trip: cegar → firmar → desvelar → verificar");
const m = 350n;
show("mensaje original m", m);

const { blinded, r } = blind(m, publicKey);
show("factor de cegado r", r);
show("gcd(r, n)", gcd(r, publicKey.n) + "   (debe ser 1: r es coprimo con n)");

// Comprobamos a mano que blinded = m · r^e mod n
const blindedManual = (m * modPow(r, publicKey.e, publicKey.n)) % publicKey.n;
show("blinded = m·r^e mod n", blinded);
check(blinded === blindedManual, "blind() coincide con el cálculo manual m·r^e mod n");

const blindSig = blindSign(privateKey, blinded);
show("blindSig = blinded^d mod n", blindSig);
console.log("   (esto lo calcula el firmante: firma el cegado SIN ver m)");

const firma = unblind(blindSig, r, publicKey);
show("firma = blindSig·r⁻¹ mod n", firma);

const recuperado = publicKey.verify(firma); // firma^e mod n
show("firma^e mod n (recupera m)", recuperado);
check(recuperado === m, "al verificar, firma^e mod n devuelve exactamente m");
check(blindVerify(m, firma, publicKey), "blindVerify(m, firma) = true");

// ---------- 2. Equivalencia con la firma directa ----------
section(2, "Equivalencia con la firma directa del mensaje");
const firmaDirecta = privateKey.sign(m); // m^d mod n
show("firma directa m^d mod n", firmaDirecta);
show("firma desvelada", firma);
check(firma === firmaDirecta, "la firma desvelada es idéntica a firmar m directamente");

// ---------- 3. Ceguera ----------
section(3, "Ceguera: el firmante nunca ve el mensaje original");
show("m", m);
show("blinded", blinded);
check(blinded !== m, "el firmante recibe blinded, que difiere de m");

// ---------- 4. Inenlazabilidad ----------
section(4, "Inenlazabilidad: mismo m, distinto r → distinto blinded");
const a = blind(m, publicKey);
const b = blind(m, publicKey);
show("blinded #1 (r aleatorio)", a.blinded);
show("blinded #2 (r aleatorio)", b.blinded);
check(a.blinded !== b.blinded, "dos cegados del mismo m son distintos (no enlazables)");

// ---------- 5. Integridad del mensaje ----------
section(5, "Integridad: la firma no vale para otro mensaje");
show("verify para m   (=350)", publicKey.verify(firma));
show("comparado con m+1 (=351)", m + 1n);
check(!blindVerify(m + 1n, firma, publicKey), "la firma de m no verifica para m+1");

// ---------- 6. Desvelado con r equivocado ----------
section(6, "Desvelado con un r equivocado → firma inválida");
const firmaMalR = unblind(blindSig, b.r, publicKey);
show("firma (r correcto)", firma);
show("firma (r equivocado)", firmaMalR);
show("verify(firma r equivocado)", publicKey.verify(firmaMalR));
check(!blindVerify(m, firmaMalR, publicKey), "desvelar con otro r no produce una firma válida");

// ---------- 7. Verificación atada a la clave correcta ----------
section(7, "La verificación está atada a la clave correcta");
const otro = generateKeyPair(512);
show("n del par impostor", otro.publicKey.n);
const blindSigImpostor = blindSign(otro.privateKey, blinded); // firma con la sk equivocada
const firmaImpostor = unblind(blindSigImpostor, r, publicKey);
show("firma del impostor", firmaImpostor);
show("verify(firma impostor) bajo n bueno", publicKey.verify(firmaImpostor));
show("m esperado", m);
check(!blindVerify(m, firmaImpostor, publicKey), "una firma con privada de otro par no verifica");
check(!blindVerify(m, firma, otro.publicKey), "una firma válida no verifica con otra pública");

// ---------- 8. Robustez ----------
section(8, "Robustez: 200 ciclos con mensajes y r aleatorios");
let okCount = 0;
for (let i = 0; i < 200; i++) {
  const msg = BigInt(Math.floor(Math.random() * 1_000_000)) + 1n;
  const { blinded: bl, r: rr } = blind(msg, publicKey);
  const s = unblind(blindSign(privateKey, bl), rr, publicKey);
  const ok = blindVerify(msg, s, publicKey);
  if (ok) okCount++;
  if (i < 3) {
    console.log(`   ciclo ${i + 1}: m=${msg}  →  verifica=${ok}`);
  }
}
console.log("   ...");
show("ciclos correctos", `${okCount}/200`);
check(okCount === 200, "los 200 ciclos verifican correctamente");

// ---------- Resumen ----------
console.log("\n════════════════════════════════════════════════════════════");
console.log(
  process.exitCode
    ? "  RESULTADO: hubo FALLOS (revisa las líneas con ✗)"
    : "  RESULTADO: todas las comprobaciones OK ✓ — la firma a ciegas funciona"
);
console.log("════════════════════════════════════════════════════════════");