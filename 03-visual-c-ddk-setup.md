---
layout: default
title: Fase 3 — Visual C++ y DDK
---

# Fase 3 — Instalación de Visual C++ 1.10 for NT y DDK (toolchain de compilación de drivers)

Continuación de [README.md](./README.md) (instalación base) y [02-kernel-debugger-setup.md](./02-kernel-debugger-setup.md) (kernel debugger). Esta fase documenta cómo armar el toolchain completo de compilación para poder escribir y compilar drivers de kernel contra NT 3.1, verificando después su comportamiento en vivo con `I386KD.EXE`.

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

Una vez instalado `MSVCNT` en `C:`, el disco `D:` (con los instaladores) ya no es necesario para el uso diario del compilador — se puede omitir del comando de arranque en sesiones futuras.

## Extraer archivos de una VM con C: en NTFS, sin arrancarla

Necesitábamos leer `TOOLS.INI` y `VCVARS32.BAT` desde el host para saber cómo Visual C++ configura sus variables de entorno (`INCLUDE`, `LIB`, `PATH`), sin tener que ir sacando capturas de pantalla de Notepad una por una.

Mismo mecanismo de `mtools` que ya se usaba en la Fase 2 para meter `I386KD.EXE` en la VM — pero en sentido inverso, para sacar archivos, con un disquete FAT intermedio:

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

## Primer build exitoso: `INPORT.SYS`

Como candidato para la primera compilación de prueba se descartaron los samples de `krnldbg` (son herramientas del propio debugger — `kdapis` es la librería del protocolo de comunicación serial, `kdexts` son extensiones para `i386kd`/`windbg`, ninguno es un driver de carga real) y se comparó tamaño de fuente entre `comm\oldpar` (73KB, con message compiler aparte) y `input\inport` (94KB en dos `.C`, sin piezas de build adicionales). Se eligió **`INPORT`** — driver del mouse serie "InPort" (bus mouse propietario Microsoft/ATI de los 90).

```
cd C:\DD\DD\SRC\INPUT\INPORT
build
```

Resultado:
```
BUILD: Compile and Link for i386
BUILD: Computing Include file dependencies:
BUILD: Examining c:\dd\dd\src\input\inport directory for files to compile.
- 3 source files (97,788 lines)
BUILD: Compiling c:\dd\dd\src\input\inport directory
Compiling - inport.rc for Unknown Target
Compiling - i386\inpcmn.c for i386
Compiling - i386\inpdep.c for i386
BUILD: Linking c:\dd\dd\src\input\inport directory
Linking Executable - C:\DD\DD\lib\i386\free\inport.sys for i386
BUILD: Done

    3 files compiled - 97564 LPS
    1 executables built
```

Toolchain confirmado de punta a punta: `CL386` compiló contra los headers del DDK, `LINK32` generó `INPORT.SYS` — un driver real de kernel. No se generaron símbolos (`INPORT.DBG`) a pesar de `NTDBGFILES=1` en `SETENV.BAT` — relevante para la sesión de debugging más abajo.

## Carga del driver como servicio (sin tocar el mouse real)

Para no arriesgar el mouse emulado de la VM, `INPORT.SYS` se registró como servicio nuevo e independiente, con arranque **manual** (no automático), usando `REGINI.EXE` (ya presente en el DDK clonado):

```
\Registry\Machine\System\CurrentControlSet\Services\TestInport
    Type = REG_DWORD 0x00000001
    Start = REG_DWORD 0x00000003
    ErrorControl = REG_DWORD 0x00000001
    ImagePath = REG_SZ System32\Drivers\INPORT.SYS
```

```
C:\DD\DD\BIN\I386\FREE\REGINI.EXE C:\INPORT.INI
```

Confirmado en `REGEDT32.EXE`, clave `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TestInport` con los 4 valores esperados.

`INPORT.SYS` copiado a `C:\WINNT\SYSTEM32\DRIVERS\` en la VM target — dato importante confirmado en la práctica: **copiar el `.SYS` a esa carpeta no lo carga por sí solo**; solo la entrada de registro (`Start`) decide si y cuándo arranca.

## Localizar el punto de carga del driver sin símbolos propios de `INPORT.SYS`

Como el build no generó `INPORT.DBG`, se usó una función del **kernel** (con símbolos vía `NTOSKRNL.DBG`) que se ejecuta en cualquier carga de driver: `NT!_IopLoadDriver`, encontrada vía búsqueda de wildcard:

```
kd> x nt!IopLoad*
80188770  NT!_IopLoadDriver
801452d6  NT!_IopLoadFileSystemDriver
801882b0  NT!_IopLoadUnloadDriver
```

```
kd> bp NT!_IopLoadDriver
kd> g
```

Disparado desde la VM target con `net start TestInport`, el breakpoint pegó, confirmando en el stack trace (`k`) la cadena completa que describe *Inside Windows NT* sobre el I/O Manager: la carga de un driver corre en un **worker thread del sistema**, asíncrono respecto al proceso que la solicitó —

```
NT!_PspSystemThreadStartup+0x50
  → NT!_ExpWorkerThread+0x88
    → NT!_IopLoadUnloadDriver+0x57
      → NT!_IopLoadDriver
```

