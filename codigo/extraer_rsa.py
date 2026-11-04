
from pathlib import Path

# Ruta del archivo PCAP
BASE = Path(__file__).resolve().parent.parent
archivo = BASE / "datos" / "transacciones_cifradas.pcap"

# Leer la captura
datos = archivo.read_bytes()

# Buscar la etiqueta RSA_PIN|
etiqueta = b"RSA_PIN|"
posicion = datos.find(etiqueta)

if posicion == -1:
    raise ValueError("No se encontro el paquete RSA_PIN")

# Extraer los campos
inicio = posicion + len(etiqueta)

salt = datos[inicio:inicio + 16]
pin_cifrado = datos[inicio + 16:inicio + 16 + 256]

# Comprobar los tamaños
assert len(salt) == 16
assert len(pin_cifrado) == 256

# Mostrar resultados
print("=== EXTRACCION RSA ===")
print("Etiqueta:", etiqueta.decode())
print("Salt:", salt.hex())
print("Longitud de salt:", len(salt), "bytes")
print("PIN cifrado:", pin_cifrado.hex())
print("Longitud PIN cifrado:", len(pin_cifrado), "bytes")


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Cargar la clave privada RSA proporcionada
ruta_clave = BASE / "datos" / "clave_privada.pem"

with open(ruta_clave, "rb") as archivo_clave:
    clave_privada = serialization.load_pem_private_key(
        archivo_clave.read(),
        password=None
    )

# Descifrar el PIN mediante RSA-OAEP con SHA-256
pin_bytes = clave_privada.decrypt(
    pin_cifrado,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Convertir el resultado a texto
pin = pin_bytes.decode("ascii")

# Verificar que corresponde a un PIN de cuatro digitos
if len(pin) != 4 or not pin.isdigit():
    raise ValueError("El PIN recuperado no tiene el formato esperado")

print("\n=== RECUPERACION DEL PIN ===")
print("Algoritmo: RSA-OAEP")
print("Hash: SHA-256")
print("PIN recuperado:", pin)
print("Verificacion: PIN de cuatro digitos valido")


from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Parametros solicitados para Scrypt
N = 2**14
R = 8
P = 1

# Configurar la derivacion de clave
kdf = Scrypt(
    salt=salt,
    length=32,
    n=N,
    r=R,
    p=P
)

# Derivar la clave AES utilizando el PIN recuperado
clave_aes = kdf.derive(pin.encode("ascii"))

# Mostrar resultados
print("\n=== DERIVACION DE CLAVE AES ===")
print("Algoritmo: Scrypt")
print("PIN utilizado:", pin)
print("Salt:", salt.hex())
print("N:", N)
print("R:", R)
print("P:", P)
print("Clave AES:", clave_aes.hex())
print("Longitud:", len(clave_aes), "bytes")
print("Longitud en bits:", len(clave_aes) * 8)


from cryptography.hazmat.primitives.ciphers.aead import AESGCM

print("\n=== DESCIFRADO AES-GCM ===")

# Buscar la primera transaccion AES-GCM
etiqueta_aes = b"AESGCM|"
posicion_aes = datos.find(etiqueta_aes)

if posicion_aes == -1:
    raise ValueError("No se encontraron transacciones AES-GCM")

# Extraer el nonce de 12 bytes
inicio_aes = posicion_aes + len(etiqueta_aes)
nonce = datos[inicio_aes:inicio_aes + 12]

# El primer paquete contiene 100 bytes de texto cifrado + tag
cifrado_tag = datos[inicio_aes + 12:inicio_aes + 12 + 100]

# Descifrar y verificar el tag de autenticacion
aesgcm = AESGCM(clave_aes)
mensaje = aesgcm.decrypt(nonce, cifrado_tag, None)

print("Algoritmo: AES-256-GCM")
print("Nonce:", nonce.hex())
print("Longitud nonce:", len(nonce), "bytes")
print("Longitud cifrado + tag:", len(cifrado_tag), "bytes")
print("Autenticacion: CORRECTA")
print("\n=== TRANSACCION RECUPERADA ===")
print(mensaje.decode("utf-8"))


from scapy.all import PcapReader, TCP
from cryptography.exceptions import InvalidTag

print("\n=== RECUPERACION DE TODAS LAS TRANSACCIONES ===")

etiqueta_aes = b"AESGCM|"
transacciones = []

# Leer los paquetes individualmente desde el PCAP
captura = PcapReader(str(archivo))

try:
    for numero, paquete in enumerate(captura, start=1):

        if TCP not in paquete:
            continue

        payload = bytes(paquete[TCP].payload)

        if not payload.startswith(etiqueta_aes):
            continue

        # Eliminar la etiqueta AESGCM|
        contenido = payload[len(etiqueta_aes):]

        if len(contenido) < 28:
            raise ValueError(
                f"Paquete {numero}: datos AES-GCM incompletos"
            )

        # Extraer nonce y texto cifrado con tag
        nonce = contenido[:12]
        cifrado_tag = contenido[12:]

        # Descifrar y comprobar autenticidad
        try:
            mensaje = aesgcm.decrypt(
                nonce,
                cifrado_tag,
                None
            ).decode("utf-8")

        except InvalidTag:
            raise ValueError(
                f"Paquete {numero}: autenticacion fallida"
            )

        # Extraer los campos de la transaccion
        partes = mensaje.split("|")

        campos = {}
        for parte in partes[1:]:
            if "=" in parte:
                clave, valor = parte.split("=", 1)
                campos[clave] = valor

        requeridos = ["ID", "DE", "A", "MONTO"]

        if not all(campo in campos for campo in requeridos):
            raise ValueError(
                f"Paquete {numero}: formato inesperado"
            )

        transacciones.append({
            "paquete": numero,
            "id": campos["ID"],
            "remitente": campos["DE"],
            "destinatario": campos["A"],
            "monto": campos["MONTO"],
            "mensaje": mensaje
        })

finally:
    captura.close()

# Comprobar cantidad recuperada
print("Transacciones recuperadas:", len(transacciones))
print("Autenticaciones correctas:", len(transacciones))

if len(transacciones) != 40:
    raise ValueError("Se esperaban 40 transacciones")

# Preparar resultados
lineas = []

for i, tx in enumerate(transacciones, start=1):
    bloque = (
        f"\n[Transaccion {i} - Paquete {tx['paquete']}]\n"
        f"ID: {tx['id']}\n"
        f"Remitente: {tx['remitente']}\n"
        f"Destinatario: {tx['destinatario']}\n"
        f"Monto: {tx['monto']}\n"
        f"Autenticacion: CORRECTA\n"
        f"Original: {tx['mensaje']}\n"
    )

    lineas.append(bloque)

# Guardar todas las transacciones
salida = BASE / "codigo" / "transacciones_descifradas.txt"
salida.write_text(
    "\n".join(lineas),
    encoding="utf-8"
)

# Mostrar un resumen en la terminal
print("\n=== PRIMERAS TRES TRANSACCIONES ===")

for bloque in lineas[:3]:
    print(bloque)

print("\n=== ULTIMAS DOS TRANSACCIONES ===")

for bloque in lineas[-2:]:
    print(bloque)

print("\nArchivo generado:", salida.name)
print("Proceso finalizado correctamente")
