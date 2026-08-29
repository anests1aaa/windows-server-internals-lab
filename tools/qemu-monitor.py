#!/usr/bin/env python3
"""
Cliente minimo para el QEMU Monitor Protocol (HMP) sobre un socket unix.

No usamos socat/nc porque no estan instalados en el host y no vale la pena
agregar una dependencia del sistema solo para esto - el modulo socket de
la stdlib alcanza.

Uso:
    qemu-monitor.py <socket> <comando...>
    qemu-monitor.py <socket> --type "texto a tipear en el guest" [--no-enter]

Ejemplos:
    qemu-monitor.py /home/s1a/WindowsNT3.1/qemu-target.monitor info status
    qemu-monitor.py /home/s1a/WindowsNT3.1/qemu-target.monitor screendump /tmp/foo.ppm
    qemu-monitor.py /home/s1a/WindowsNT3.1/qemu-target.monitor --type "copy a:\\hello.c c:\\"

--type manda el texto como una secuencia de "sendkey" (una tecla HMP por
caracter, con Enter final salvo --no-enter) - no hay forma de mandar un
string de una sola vez en HMP, cada tecla es su propio comando de monitor.
"""
import socket
import sys
import time

PROMPT = b"(qemu) "

# Mapeo caracter -> nombre de tecla QEMU (qemu-keymap). Solo cubre lo
# necesario para paths/comandos DOS-NT tipicos (letras, digitos, ':' '\' '.' etc).
_SHIFT_MAP = {
    ':': 'semicolon', '"': 'apostrophe', '<': 'comma', '>': 'dot',
    '?': 'slash', '_': 'minus', '+': 'equal', '|': 'backslash',
    '{': 'bracket_left', '}': 'bracket_right', '~': 'grave',
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
    '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
}
_PLAIN_MAP = {
    ' ': 'spc', '\\': 'backslash', '.': 'dot', ',': 'comma', '/': 'slash',
    '-': 'minus', '=': 'equal', ';': 'semicolon', "'": 'apostrophe',
    '[': 'bracket_left', ']': 'bracket_right', '`': 'grave',
}


def char_to_keys(ch):
    if ch.isalpha():
        return [f"shift-{ch.lower()}"] if ch.isupper() else [ch.lower()]
    if ch.isdigit():
        return [ch]
    if ch in _SHIFT_MAP:
        return [f"shift-{_SHIFT_MAP[ch]}"]
    if ch in _PLAIN_MAP:
        return [_PLAIN_MAP[ch]]
    raise ValueError(f"sin mapeo de tecla para {ch!r}")


def read_until_prompt(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if buf.rstrip().endswith(PROMPT.rstrip()):
            break
    return buf


def run_command(s, command):
    s.sendall(command.encode() + b"\n")
    return read_until_prompt(s)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    sock_path = sys.argv[1]

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        # Banner inicial + primer prompt "(qemu) "
        read_until_prompt(s)

        if sys.argv[2] == "--type":
            rest = sys.argv[3:]
            no_enter = "--no-enter" in rest
            text = " ".join(a for a in rest if a != "--no-enter")
            for ch in text:
                for key in char_to_keys(ch):
                    run_command(s, f"sendkey {key}")
            if not no_enter:
                run_command(s, "sendkey ret")
            return

        command = " ".join(sys.argv[2:])
        out = run_command(s, command)

    # El monitor re-dibuja la linea entera (readline-style) en cada tecla,
    # con secuencias ANSI "\x1b[K" (borrar hasta fin de linea) + "\x1b[D"*n
    # (mover el cursor). No vale la pena emular una terminal solo para esto:
    # el ULTIMO "\x1b[K" en el output marca el fin del eco del comando (al
    # apretar Enter no hay mas "\x1b[D" despues), asi que todo lo que sigue
    # es la respuesta real + el prompt final.
    marker = b"\x1b[K"
    idx = out.rfind(marker)
    tail = out[idx + len(marker):] if idx != -1 else out
    text = tail.decode(errors="replace").replace("\r\n", "\n")
    if text.rstrip().endswith("(qemu)"):
        text = text.rstrip()[: -len("(qemu)")]
    print(text.strip())


if __name__ == "__main__":
    main()
