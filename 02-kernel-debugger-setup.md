---
layout: default
title: Fase 2 — Kernel Debugger
---

# Fase 2 — Configuración del Kernel Debugger (I386KD.EXE)

Continuación de [README.md](./README.md) (instalación base de NT 3.1 Advanced Server). Esta fase documenta cómo conectar un kernel debugger real a la VM instalada, para poder verificar en vivo los conceptos que describe *Inside Windows NT* (Helen Custer, 1992).

## Por qué no usamos WinDbg

`WinDbg.exe` es la contraparte gráfica de `I386KD.EXE` — habla el mismo protocolo de debug por debajo, pero no venía incluido con NT 3.1 (se distribuía aparte con el Win32 SDK) y tenía fama de inestable en esa época. `I386KD.EXE` es la herramienta de línea de comandos **nativa** de esta versión, incluida en el propio CD de instalación, y es la que corresponde usar para mantener coherencia con la época del sistema que se está estudiando.

## El problema de origen: NTFS bloquea el método de copia por DOS

Una vez que `C:` se convierte a NTFS durante la instalación, el disquete de MS-DOS (que usamos para copiar los archivos de instalación) deja de servir para transferir archivos nuevos — DOS no sabe leer NTFS. La solución: como NT sí lee disquetes **FAT** sin problema (la conversión a NTFS solo afectó al disco duro, no a medios removibles), se arman los disquetes con las herramientas necesarias directamente en el host Linux, usando `mtools`, y se insertan en la VM ya instalada — sin pasar por DOS en ningún momento.

## Paso 1: Extraer el contenido del CD en el host

```bash
cd ~/WindowsNT3.1
mkdir -p CDISO
7z x CD.iso -oCDISO
```

`7z` lee imágenes ISO9660 directamente, sin necesidad de montar nada ni usar ninguna VM.

## Paso 2: Ubicar el debugger y los símbolos dentro del CD extraído

```
CDISO/SUPPORT/DEBUG/I386/I386KD.EXE       ← el debugger en sí
CDISO/SUPPORT/DEBUG/I386/IMAGEHLP.DLL     ← dependencia necesaria
CDISO/SUPPORT/DEBUG/I386/SYMBOLS/EXE/NTOSKRNL.DBG   ← símbolos del kernel
CDISO/SUPPORT/DEBUG/I386/SYMBOLS/DLL/HAL.DBG        ← símbolos del HAL (variante genérica PC)
```

> Los símbolos están organizados por tipo de archivo original (`EXE`, `DLL`, `SYS`, `DRV`, etc.), en formato `.DBG` (COFF), no `.PDB` — formato previo al que se usa en versiones modernas de Windows.
> Hay variantes de HAL para hardware específico (`HALNCR.DBG`, `HALWYSE7.DBG`, etc.) — para una VM genérica corresponde `HAL.DBG` a secas.

## Paso 3: Armar un disquete FAT con lo esencial

```bash
qemu-img create -f raw kdtools.img 1440K
mformat -i kdtools.img -f 1440 ::

mcopy -i kdtools.img CDISO/SUPPORT/DEBUG/I386/I386KD.EXE ::I386KD.EXE
mcopy -i kdtools.img CDISO/SUPPORT/DEBUG/I386/IMAGEHLP.DLL ::IMAGEHLP.DLL
mcopy -i kdtools.img CDISO/SUPPORT/DEBUG/I386/SYMBOLS/EXE/NTOSKRNL.DBG ::NTOSKRNL.DBG
mcopy -i kdtools.img CDISO/SUPPORT/DEBUG/I386/SYMBOLS/DLL/HAL.DBG ::HAL.DBG
```

Estos 4 archivos ocupan ~715KB de los 1.44MB disponibles — sobra espacio para sumar más símbolos (`.DBG` de otros componentes) a medida que el estudio del libro lo requiera.

## Paso 4: Insertar el disquete en la VM (ya instalada y logueada) sin cerrarla

Vía el monitor de QEMU, sin reiniciar la VM:

```
Ctrl+Alt+2                                          # entrar al monitor
change floppy0 /ruta/completa/kdtools.img
Ctrl+Alt+1                                          # volver a la VM
```

Dentro de NT, en el Command Prompt:

```
md C:\I386KD
copy A:\I386KD.EXE C:\I386KD\
copy A:\IMAGEHLP.DLL C:\I386KD\
md C:\SYMBOLS
copy A:\NTOSKRNL.DBG C:\SYMBOLS\
copy A:\HAL.DBG C:\SYMBOLS\
```

## Paso 5: Activar el puerto de debug en BOOT.INI

`BOOT.INI` es un archivo oculto, de sistema y de solo lectura — hay que quitarle esos atributos antes de editarlo:

```
attrib -r -s -h C:\boot.ini
notepad C:\boot.ini
```

Agregar una nueva entrada en `[operating systems]` (copiar la línea existente y sumar los switches al final, **en una sola línea continua**, sin salto de línea real):

```ini
[boot loader]
timeout=30
default=multi(0)disk(0)rdisk(0)partition(1)\winnt

[operating systems]
multi(0)disk(0)rdisk(0)partition(1)\winnt="Windows NT Advanced Server 3.10"
multi(0)disk(0)rdisk(0)partition(1)\winnt="Windows NT Advanced Server 3.10 [DEBUG]" /DEBUG /DEBUGPORT=COM1 /BAUDRATE=19200
c:\="MS-DOS"
```

Guardar y volver a proteger el archivo:
```
attrib +r +s +h C:\boot.ini
```

## Paso 6: Clonar el disco como "máquina debugger"

Como el disco ya tiene NT instalado y `I386KD.EXE` + símbolos copiados, la forma más simple de tener una segunda máquina para correr el debugger es clonar el disco (apagando la VM primero, para evitar corrupción):

```bash
cp nt31.img nt31-debugger.img
```

## Paso 7: Levantar ambas VMs conectadas por serial virtual

Además del serial de debug, cada VM levanta su propio **QEMU monitor** en un socket unix (`-monitor unix:...,server,nowait`). El monitor es un canal de control aparte del debug kernel: habla el protocolo HMP de QEMU (no el protocolo de `i386kd`), corre en el *host* que emula la VM, y permite mandarle comandos al hypervisor — `screendump` para capturar el framebuffer sin depender de que la ventana gráfica esté visible, `sendkey` para inyectar teclas, `system_powerdown`/`quit`, `info status`, etc. Con esto el asistente puede "ver" y controlar la VM por socket en vez de depender de la ventana de QEMU del host. Ver `tools/qemu-monitor.py` para el cliente usado (no hay `socat`/`nc` instalados, así que es un cliente mínimo en Python contra `socket` de la stdlib).

**VM debugger** (aloja `I386KD.EXE` — **servidor** del socket serial):
```bash
qemu-system-i386 -m 64 -hda nt31-debugger.img -M pc,acpi=off -cpu 486 \
  -serial tcp::4555,server,nowait \
  -monitor unix:/home/s1a/WindowsNT3.1/qemu-debugger.monitor,server,nowait &
```
→ En el menú de boot, elegir la entrada **normal** (sin `[DEBUG]` — esta VM no está siendo depurada).

**VM objetivo** (la que se va a depurar — **cliente** del socket serial):
```bash
qemu-system-i386 -m 64 -hda nt31.img -M pc,acpi=off -cpu 486 \
  -serial tcp:127.0.0.1:4555 \
  -monitor unix:/home/s1a/WindowsNT3.1/qemu-target.monitor,server,nowait &
```
→ En el menú de boot, elegir la entrada con `[DEBUG]`.

**Por qué la VM debugger es el servidor y no la objetivo (cambiado 2026-08-28):** originalmente era al revés (objetivo=servidor, debugger=cliente), siguiendo el orden "natural" de quién depura a quién. Pero en la práctica la VM debugger es la que se deja corriendo largo rato (con `i386kd` ya escuchando), mientras que la VM objetivo es la que se reinicia todo el tiempo durante el trabajo de reversing. Con objetivo=servidor, cada reinicio de la objetivo mataba el socket y dejaba a la debugger con un cliente TCP colgado — greglar esto con `reconnect-ms=<n>` (el reemplazo del deprecado `reconnect=<segundos>`) resultó en un crash reproducible de QEMU 11.1.0 (`SIGABRT`/core dump) cuando el cliente arranca con `reconnect-ms` y todavía no hay nada escuchando del otro lado. Invirtiendo los roles el problema desaparece por completo: la debugger (servidor) puede arrancar sola en cualquier momento sin depender de que la objetivo ya esté arriba, y cada reinicio de la objetivo (cliente) simplemente hace un connect() nuevo contra un socket que ya está escuchando — sin reconnect, sin crash, sin tener que tocar la debugger.

Ejemplo de uso del monitor una vez arriba (capturar pantalla sin la ventana gráfica):
```bash
python3 tools/qemu-monitor.py /home/s1a/WindowsNT3.1/qemu-target.monitor screendump /tmp/target.ppm
magick /tmp/target.ppm /tmp/target.png   # el monitor solo escribe PPM; se convierte para poder verla
```

## Paso 8: Lanzar el debugger

Dentro de la VM debugger, en el Command Prompt:

```
cd C:\I386KD
set _NT_DEBUG_PORT=COM1
set _NT_DEBUG_BAUD_RATE=19200
set _NT_SYMBOL_PATH=C:\SYMBOLS
i386kd
```

Salida esperada:
```
Microsoft(R) Windows NT Kernel Debugger
Version 1.00
(C) 1991 Microsoft Corp.

Symbol search path is: C:\SYMBOLS;.;
KD: Unable to load debug information for ntoskrnl.exe
KD: waiting to connect...
KD: baud rate reset to 19200
KD: Kernel Debugger connection established.
```

## Paso 9: Forzar un break e interactuar con el kernel en vivo

La conexión queda establecida, pero el sistema objetivo sigue ejecutando normalmente hasta que se fuerza una interrupción:

```
Ctrl+C          (en la ventana del debugger)
```

Esto detiene la ejecución del kernel remoto en el punto exacto donde estaba, y habilita el prompt interactivo `kd>`.

### Comandos verificados funcionando

| Comando | Qué muestra |
|---|---|
| `?` | Lista completa de comandos disponibles |
| `r` | Estado de los registros de la CPU en el instante del break |
| `k` | Stack trace (pila de llamadas) actual |

> Nota: ni `r` ni `k` requieren símbolos cargados para funcionar (son datos crudos: registros y direcciones en hex). Que ambos funcionen bien **no** es prueba de que los símbolos hayan cargado correctamente — para eso hace falta un comando que sí dependa de ellos, como `ln <dirección>` (ver Fase 3).

Ejemplo de sesión real:
```
kd> r
eax=00000201 ebx=00000002 ecx=0000001c edx=00000000 esi=801b5800 edi=00000001
eip=8015e109 esp=01ac6f0 ebp=801ac6f8 iopl=0 ...

kd> k
ChildEBP RetAddr
801ac6ec 80113c02
801ac6f8 021128ed
```

## Notas y problemas menores encontrados

- **Baud rate:** hay reportes conocidos de que algunos emuladores modernos envían datos más rápido de lo esperado a 19200 baudios, causando que el debugger parezca colgado en "waiting to connect". Si pasa, esperar unos segundos antes de asumir fallo.
- **"waiting to connect..." que nunca progresa (2026-08-28):** distinto del problema de baud rate de arriba — acá el socket TCP está perfectamente conectado (se puede confirmar con `ss -tin`, hay tráfico real en ambas direcciones), pero `i386kd` se queda colgado igual, a veces por minutos. Causa real: el stub de kernel debugger de NT es *pasivo* — no manda un paquete "acá estoy" espontáneamente. Solo completa el handshake del protocolo KD cuando pasa uno de dos eventos: (a) el kernel pega una excepción/breakpoint real, o (b) el debugger manda un pedido explícito de break-in, que es lo que hace `Ctrl+C` en la ventana de `i386kd`. Si la VM objetivo está tranquila (ej. parada en la pantalla de login, sin disparar nada), no hay ningún evento (a) esperando pasar, así que sin mandar `Ctrl+C` una vez el handshake nunca se completa por más que se espere. Confirmación de que esto es lo que pasa: al mandar `Ctrl+C`, el break resultante cae en `NT!_KeUpdateSystemTime+0x109` — la ISR del timer, el primer punto "seguro" donde el kernel revisa si hay un break-in pendiente. **Solución:** después de loguear en la VM debugger y lanzar `i386kd`, si se queda en "waiting to connect..." más de unos segundos, mandar `Ctrl+C` una vez para forzar la sincronización inicial (no hace falta que la VM objetivo esté haciendo nada en particular).
- **VM debugger con warning al arrancar:** al clonar el disco, la copia puede mostrar *"At least one service or driver failed during system startup"* — es esperable por diferencias mínimas de detección de hardware entre el disco original y la copia; no afecta el uso de `I386KD.EXE`, se puede descartar con OK.

## Estado del lab a partir de acá

✅ NT 3.1 Advanced Server instalado y funcional
✅ Kernel debugger (`I386KD.EXE`) conectado entre dos VMs vía serial virtual
✅ Símbolos de kernel (`NTOSKRNL.DBG`) y HAL (`HAL.DBG`) cargados
✅ Break manual funcional, registros y stack trace verificados


