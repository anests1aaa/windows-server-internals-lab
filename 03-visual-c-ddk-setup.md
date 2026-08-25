# Fase 3 — Instalación de Visual C++ 1.10 for NT y DDK (toolchain de compilación de drivers)

Continuación de [README.md](./README.md) (instalación base) y [02-kernel-debugger-setup.md](./02-kernel-debugger-setup.md) (kernel debugger). Esta fase documenta cómo armar el toolchain completo de compilación para poder escribir y compilar drivers de kernel contra NT 3.1, verificando después su comportamiento en vivo con `I386KD.EXE`.

## Objetivo

Tener, dentro de la VM debugger (`nt31-debugger.img`), un entorno funcional de:
- Compilador C para i386 (`CL386.EXE`)
- Headers y libs de kernel del DDK (`NTDDK.H`, etc.)
- `BUILD.EXE` (el driver de build oficial del DDK)
- Samples de drivers para usar como punto de partida

## Fuentes de software (adicionales al README original)

| Componente | Origen | Notas |
|---|---|---|
| Windows NT 3.1 Win32 SDK and DDK (Oct 1994, MSDN ISO) | WinWorld | Trae compilador i386 para MIPS/Alpha pero **no** para x86 — ver más abajo |
| Microsoft Visual C++ 1.10 for Windows NT & 32s | archive.org | Trae `CL386.EXE`, el compilador i386 que falta en el DDK |

## ⚠️ Hallazgo: el DDK de NT 3.1 no trae compilador para i386

El SDK/DDK bundle de esta build (Oct 1994) incluye carpetas `ALPHA`, `MIPS` e `I386`, pero **`I386` son archivos de instalación de NT para esa arquitectura, no el compilador**. El compilador C (`CL.EXE`) solo está presente en `MSTOOLS/BIN/MIPS` y `MSTOOLS/BIN/ALPHA` — confirmado también por reportes del foro de WinWorld sobre este mismo paquete.

**Solución:** conseguir **Microsoft Visual C++ 1.10 for Windows NT & 32s** aparte (mismo período/versión del compilador que el usado internamente por el SDK para MIPS/Alpha — versión 8.00). Ahí sí está `CL386.EXE`, junto con `LINK32.EXE`, `LIB32.EXE`, `NMAKE.EXE` y el runtime `DOSXNT.EXE` (DPMI, permite correr el toolchain de 32 bits desde DOS/NT sin problema).

## Comandos usados

```bash
# Crear disco intermedio para Visual C++
qemu-img create -f qcow2 devtools.img 200M

# Armar ISO del instalador desde el host (mkisofs, paquete cdrtools en Arch)
cd ~/Downloads/VisualC
mkisofs -o msvcnt.iso -J -r MSVCNT/

# VM temporal de DOS para preparar el disco intermedio
qemu-system-i386 -m 32 -hda devtools.img -fda dos1.img -cdrom ~/Downloads/VisualC/msvcnt.iso -boot a -M pc,acpi=off -cpu 486
```

Mismo procedimiento se repitió para el DDK (74MB), con un disco intermedio más chico:

```bash
# Extraer solo la carpeta DDK del SDK completo (no hace falta I386/MIPS/ALPHA, que son archivos de instalación de NT)
cd "~/Downloads/.../SDKISO"
mkisofs -o ddk.iso -J -r DDK/

qemu-img create -f qcow2 ddktools.img 150M
qemu-system-i386 -m 32 -hda ddktools.img -fda dos1.img -cdrom ddk.iso -boot a -M pc,acpi=off -cpu 486
```

## Instalación de Visual C++ dentro de la VM debugger

Con `devtools.img` ya preparado, se arrancó la VM debugger con dos discos:

```bash
qemu-system-i386 -m 64 -hda nt31-debugger.img -hdb devtools.img -M pc,acpi=off -cpu 486
```

`devtools.img` apareció correctamente como `D:` en el File Manager (confirmando que el problema era específicamente ATAPI, no un límite general de NT con discos adicionales). Desde ahí:

```
D:\MSVCNT\SETUP.EXE
```

- Tipo de instalación: **Complete** (había espacio de sobra, 364MB libres de 499MB totales — no hacía falta optimizar con Custom)
- Al finalizar, el instalador preguntó cómo manejar `TOOLS.INI`: se eligió **"Make changes now and back up current version"** (en vez de la opción por default, que solo escribe una copia modificada en otro lugar sin aplicarla) — así los cambios quedan aplicados directamente y el archivo es inspeccionable después

Una vez instalado `MSVCNT` en `C:`, el disco `D:` (con los instaladores) ya no es necesario para el uso diario del compilador — se puede omitir del comando de arranque en sesiones futuras.

## Extraer archivos de una VM con C: en NTFS, sin arrancarla

Necesitábamos leer `TOOLS.INI` y `VCVARS32.BAT` desde el host para saber cómo Visual C++ configura sus variables de entorno (`INCLUDE`, `LIB`, `PATH`), sin tener que ir sacando capturas de pantalla de Notepad una por una.

**Intento fallido: `libguestfs` (`guestmount`, `virt-copy-out`, `guestfish`).** Los tres fallaron con el mismo error de fondo:
```
mount: wrong fs type, bad option, bad superblock on /dev/sda1
```
La causa es que **NT 3.1 usa una versión muy temprana de NTFS** ("NTFS v1.0"), con estructuras internas distintas a las que reconoce el driver `ntfs-3g`/`ntfs3` moderno de Linux — el mismo driver que usan por debajo todas las herramientas de `libguestfs`. `virt-copy-out` además falla con un segundo problema previo: intenta hacer inspección automática del SO en el disco y no reconoce NT 3.1 como sistema instalado, así que ni siquiera llega a montar.

**Solución que funcionó: disquete FAT intermedio.** Mismo mecanismo de `mtools` que ya se usaba en la Fase 2 para meter `I386KD.EXE` en la VM — pero en sentido inverso, para sacar archivos:

```bash
qemu-img create -f raw extract.img 1440K
mformat -i extract.img -f 1440 ::
```

Insertar el disquete vía monitor de QEMU sin apagar la VM:
```
Ctrl+Alt+2
change floppy0 /home/s1a/WindowsNT3.1/extract.img
Ctrl+Alt+1
```

Copiar el archivo deseado al disquete desde dentro de NT:
```
copy C:\MSVCNT\TOOLS.INI A:\
copy C:\MSVCNT\BIN\VCVARS32.BAT A:\
```

Y leerlo desde el host con `mtools` (que sí funciona perfecto con FAT, sin ningún problema de compatibilidad):
```bash
mtype -i extract.img ::TOOLS.INI
mtype -i extract.img ::VCVARS32.BAT
```

Esto evita por completo el problema de NTFS viejo, ya que el disquete es FAT de punta a punta.

## Configuración de variables de entorno

`TOOLS.INI` solo contiene configuración del profiler (exclusión de libs) — **no** las variables de compilación. Esas viven en `VCVARS32.BAT`:

```batch
@echo off
set PATH=C:\MSVCNT\BIN;%PATH%
set INCLUDE=C:\MSVCNT\INCLUDE;C:\MSVCNT\MFC\INCLUDE;%INCLUDE%
set LIB=C:\MSVCNT\LIB;C:\MSVCNT\MFC\LIB;%LIB%
set INIT=C:\MSVCNT;%INIT%
```

Para sumar las rutas del DDK sin romper esta configuración base, se armó un segundo batch, `SETDDK.BAT`, que llama a `VCVARS32.BAT` primero y extiende las variables después:

```batch
@echo off
call C:\MSVCNT\BIN\VCVARS32.BAT
set INCLUDE=D:\INC;%INCLUDE%
set LIB=D:\LIB;%LIB%
set PATH=D:\BIN\I386\FREE;%PATH%
```

`SETDDK.BAT` se armó en el host y se metió en la VM con el mismo mecanismo del disquete FAT (esta vez en sentido host → VM, como en la Fase 2):

```bash
mcopy -i extract.img /tmp/setddk.bat ::SETDDK.BAT
```

## Comando de arranque para desarrollo (post-setup)

```bash
qemu-system-i386 -m 64 -hda nt31-debugger.img -hdb ddktools.img -M pc,acpi=off -cpu 486
```

Dentro de NT, antes de compilar:
```
C:\SETDDK.BAT
```

## Estructura final de discos en la VM debugger

| Unidad | Contenido |
|---|---|
| `C:` | NT 3.1 Advanced Server + Visual C++ 1.10 instalado (`C:\MSVCNT`) + `I386KD` + `SYMBOLS` (de la Fase 2) |
| `D:` | DDK completo (`INC`, `LIB`, `SRC`, `BIN`, `DOC`) |

## Problemas encontrados y descartados (para referencia)

| Intento | Resultado | Causa |
|---|---|---|
| `-cdrom` con ISO del instalador de Visual C++, sobre NT ya instalado | CD nunca aparece como unidad, sin error visible | Mismo bug ATAPI del README original — no es solo del instalador de NT, es de todo NT 3.1 |
| `guestmount -m /dev/sda1` sobre `nt31-debugger.img` | `wrong fs type, bad superblock` | NTFS v1.0 (NT 3.1) no es reconocido por el driver `ntfs-3g` moderno |
| `virt-copy-out` sin inspección manual | `no operating system was found on this disk` | El inspector automático de libguestfs no reconoce NT 3.1 como SO instalado |
| `guestfish` + `mount-ro` manual | Mismo error de superbloque que `guestmount` | Confirma que el problema es el driver NTFS, no la herramienta específica |

## Próximos pasos del proyecto

- [x] Instalar Visual C++ 1.10 for NT (compilador i386) en la VM debugger
- [x] Instalar DDK de NT 3.x (headers, libs, samples, `BUILD.EXE`)
- [x] Resolver acceso a archivos de una VM con `C:` en NTFS desde el host (vía disquete FAT + `mtools`, dado que `libguestfs` no soporta NTFS v1.0)
- [x] Armar `SETDDK.BAT` combinando entorno de Visual C++ + DDK
- [ ] Compilar un primer sample simple de `DDK/SRC` con `BUILD.EXE` como prueba de humo del toolchain completo
- [ ] Cargar el driver resultante en la VM objetivo y verificar su comportamiento en vivo con `I386KD.EXE`
- [ ] Verificar en vivo las estructuras del Object Manager / I/O Manager descritas en *Inside Windows NT* (pendiente del README original)

## Créditos y fuentes

- [WinWorld](https://winworldpc.com) — SDK/DDK de NT 3.x
- [Internet Archive — Microsoft Visual C++ 1.10 for Windows NT](https://archive.org/details/microsoft-visual-c-1.10-for-windows-nt)
- Foro de WinWorld — confirmación de que el DDK de NT 3.x requiere Visual C++ 1.0 for NT para compilador i386
- *Inside Windows NT* — Helen Custer (Microsoft Press, 1992)
