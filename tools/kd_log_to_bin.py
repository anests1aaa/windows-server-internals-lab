#!/usr/bin/env python3
"""
Convierte un log de volcado `db` de i386kd (via .logopen/.logclose) a un
binario crudo, listo para importar en Ghidra como Raw Binary.

Uso:
    kd_log_to_bin.py <entrada.log> <salida.bin>

Formato de línea de datos de `db`, fijo:
    80125f86  81 ec 94 00 00 00 53 56-57 55 2b c0 89 44 24 1c  ......SVWU+..D$.
    ^direccion  ^bloque hex (16 bytes, separador " " o "-")     ^columna ASCII

No usamos una heurística de "buscar el espacio doble" para separar el bloque
hex de la columna ASCII, porque un byte que valga 0x20 se renderiza como un
espacio real en la columna ASCII y rompería esa heurística. En cambio,
anclamos un regex a la estructura exacta: 8 hex de dirección + dos espacios +
una repetición de "2 hex seguidos de separador" hasta el último byte de la
línea (que no lleva separador, lo sigue el espacio doble hacia la columna
ASCII). Esto es correcto sin importar qué bytes haya, incluida la última
línea si el tamaño total no es múltiplo de 16.
"""
import re
import sys

LINE_RE = re.compile(
    r'^[0-9a-fA-F]{8}  ((?:[0-9a-fA-F]{2}[ -])*[0-9a-fA-F]{2})  '
)


def parse_log(path):
    data = bytearray()
    with open(path, "r") as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue  # línea de control (log file opened, kd> db ..., etc.)
            hex_bytes = re.findall(r'[0-9a-fA-F]{2}', m.group(1))
            data.extend(int(b, 16) for b in hex_bytes)
    return bytes(data)


def main():
    if len(sys.argv) != 3:
        print(f"Uso: {sys.argv[0]} <entrada.log> <salida.bin>", file=sys.stderr)
        sys.exit(1)

    log_path, bin_path = sys.argv[1], sys.argv[2]
    data = parse_log(log_path)

    if not data:
        print("ADVERTENCIA: no se extrajo ningún byte — revisar el formato del log", file=sys.stderr)

    with open(bin_path, "wb") as f:
        f.write(data)

    print(f"{len(data)} bytes ({hex(len(data))}) escritos en {bin_path}")


if __name__ == "__main__":
    main()
