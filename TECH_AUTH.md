# tech_auth: solo el técnico puede conectarse

## Qué hace
Los equipos con este build **solo aceptan sesiones firmadas con tu llave privada**.
En el equipo del cliente solo hay una clave PÚBLICA (no es secreta). Conocer el DNS,
la clave del servidor o tener un RustDesk común no sirve para entrar.
No se toca el servidor (hbbs/hbbr): la clave del servidor y los clientes actuales siguen igual.

## Archivos
- `src/tech_auth.rs`  módulo (firma, verificación, archivo de llave cifrado). Con pruebas.
- `src/server/connection.rs`  verifica la firma al recibir la conexión y bloquea toda otra forma de autorizar.
- `src/client.rs`  el técnico firma el desafío del equipo remoto.
- `tools/tech-keygen`  genera y prueba la llave. `lanzar-tecnico.ps1`  lanzador del pendrive.

## Paso a paso
1. Generar la llave (en tu PC):  `tech-keygen gen tech_key.enc`  -> guarda `tech_key.enc` en el pendrive (+ una copia de respaldo) y anotá la CLAVE PÚBLICA que imprime.
2. Compilar RustDesk con la variable de entorno `TECH_PUBKEY=<clave pública>`.
   Sin esa variable el módulo queda apagado y el cliente se comporta como el original.
3. Instalar el .msi nuevo en los clientes (encima del actual: mantiene servidor y clave).
4. En tu PC usar `lanzar-tecnico.ps1` (pendrive + contraseña = dos factores).

## Qué cambia en la práctica
- Equipo con build nuevo: acepta solo conexiones firmadas. La contraseña ya no se usa ni se pide.
- Equipo con build viejo: funciona como antes hasta que lo actualices (no es seguro hasta entonces).
- Direct IP y "cambiar de lado" dejan de funcionar hacia equipos protegidos.
- Pérdida del pendrive sin la contraseña: no sirve. Pérdida de la llave sin respaldo: hay que recompilar con otra clave pública.
