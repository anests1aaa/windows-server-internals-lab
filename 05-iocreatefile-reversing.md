---
layout: default
title: Fase 5 — IoCreateFile reversing
---

# IoCreateFile — reversing del kernel NT 3.1

**Función objetivo:** `NT!_IoCreateFile` en `ntoskrnl.exe` (build 3.10.5098.1)  
**Dirección base:** `0x80168740`  
**Herramientas:** Ghidra 11 + `i386kd` (kernel debugger NT 3.1)

---

## 1. Reconstrucción de tipos DDK auténticos para Ghidra

El primer obstáculo fue que Ghidra no conoce los tipos NT internos (`IO_STATUS_BLOCK`, `OBJECT_ATTRIBUTES`, `KPROCESSOR_MODE`, etc.). Los headers modernos de WDK no sirven porque las estructuras cambiaron. Necesitamos los headers originales de **NT DDK octubre 1994**.

### Proceso para generar el `.gdt`

```bash
# 1. Crear symlinks en minúscula para los headers en mayúscula
for dir in ddk_extract/INC vc_extract/INCLUDE; do
  (cd "$dir" && for f in *; do
    lower=$(echo "$f" | tr '[:upper:]' '[:lower:]')
    [ "$f" != "$lower" ] && [ ! -e "$lower" ] && ln -s "$f" "$lower"
  done)
done

# 2. Preprocesar a un .h plano con gcc -E
gcc -E -xc -I ddk_extract/INC -I vc_extract/INCLUDE \
    -D_X86_ -Di386 ntddk_wrapper.c -o ntddk_flat.i

# 3. Limpiar líneas # y __declspec
sed -i -E \
  -e '/^# [0-9]/d' \
  -e '/^#pragma/d' \
  -e 's/__declspec\([^)]*\)//g' ntddk_flat.i

# Renombrar para que Ghidra lo acepte
cp ntddk_flat.i ntddk_flat.h
```

**`ntddk_wrapper.c`** incluye `<ntddk.h>` y agrega manualmente el prototipo de `IoCreateFile` (no está declarado en el DDK público de 1994, solo aparece en comentarios):

```c
NTSTATUS
IoCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG Disposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength,
    IN CREATE_FILE_TYPE CreateFileType,
    IN PVOID ExtraCreateParameters OPTIONAL,
    IN ULONG Options
    );
```

Luego en Ghidra: **File → Parse C Source** → agregar `ntddk_flat.h` → **Parse to Program** → guarda como `nt31_ddk.gdt` en el Data Type Manager.

---

## 2. Firma de la función

`IoCreateFile` recibe **14 parámetros** (stdcall):

| # | Nombre | Tipo | Descripción |
|---|--------|------|-------------|
| 1 | `FileHandle` | `PHANDLE` | OUT — handle resultante |
| 2 | `DesiredAccess` | `ACCESS_MASK` | permisos solicitados |
| 3 | `ObjectAttributes` | `POBJECT_ATTRIBUTES` | nombre, atributos |
| 4 | `IoStatusBlock` | `PIO_STATUS_BLOCK` | OUT — resultado de la operación |
| 5 | `AllocationSize` | `PLARGE_INTEGER` | tamaño inicial (opcional) |
| 6 | `FileAttributes` | `ULONG` | atributos del archivo |
| 7 | `ShareAccess` | `ULONG` | compartición |
| 8 | `Disposition` | `ULONG` | CREATE/OPEN/TRUNCATE... |
| 9 | `CreateOptions` | `ULONG` | opciones del IRP |
| 10 | `EaBuffer` | `PVOID` | Extended Attributes (opcional) |
| 11 | `EaLength` | `ULONG` | longitud del EaBuffer |
| 12 | `CreateFileType` | `CREATE_FILE_TYPE` | None / NamedPipe / Mailslot |
| 13 | `ExtraCreateParameters` | `PVOID` | parámetros extra (opcional) |
| 14 | `Options` | `ULONG` | flags internos del kernel |

Pseudocódigo de Ghidra tras aplicar los tipos DDK:

![Ghidra decompiler mostrando IoCreateFile con tipos DDK aplicados](img/iocreatefile-ghidra-pseudocode-header.png)

---

## 3. Determinación de RequestorMode

Lo primero que hace la función es saber desde dónde fue llamada: ¿kernel o usermode?

```c
// Leer PreviousMode del KTHREAD actual
// FS:[0x124] = KPCR->PrcbData.CurrentThread (puntero al KTHREAD)
// KTHREAD+0x1d4 = PreviousMode (KPROCESSOR_MODE)
local_5 = *(char *)(unaff_FS_OFFSET[0x49] + 0x1d4);

// Flag IO_NO_PARAMETER_CHECKING (0x100):
// Si está presente, forzar KernelMode sin importar el caller real
if ((param_14 & 0x100) != 0) {
    local_5 = '\0';  // KernelMode = 0
}
```

- `KernelMode = 0` → el caller es de confianza, no se validan punteros
- `UserMode = 1` → el caller viene de ring 3, hay que validar todo

---

## 4. Estructura SEH — el frame de excepción MSVC

`IoCreateFile` usa `__try/__except` para proteger los accesos a memoria de usermode. El compilador MSVC para x86 implementa esto con una cadena de registros de excepción instalados en `FS:[0]`.

### Layout del frame en el stack

El array `local_3c[4]` mapea el registro de excepción MSVC:

| Índice | Offset (ebp) | Campo | Valor |
|--------|-------------|-------|-------|
| `[0]` | `[ebp-0x38]` | `Next` | puntero al frame anterior en `FS:[0]` |
| `[1]` | `[ebp-0x34]` | `Handler` | `0x8010fdb8` = `_except_handler3` |
| `[2]` | `[ebp-0x30]` | `ScopeTable` | `0x8019db00` |
| `[3]` | `[ebp-0x2c]` | `TryLevel` | `-1` = inactivo, `0` = try#0, `1` = try#1 |

Ghidra muestra los valores hardcodeados antes de instalar el frame:

![Ghidra mostrando los valores del SEH frame: 0xffffffff, 0x8019db00, 0x8010fdb8](img/iocreatefile-ghidra-seh-frame-values.png)

Assembly real capturado con `i386kd` mostrando cómo el compilador instala el frame en `FS:[0]`:

![i386kd assembly mostrando la instalación del SEH frame](img/iocreatefile-kd-seh-frame-asm.png)

### ScopeTable en `0x8019db00`

La ScopeTable describe los dos bloques `__try` independientes de la función:

```
kd> dd 8019db00 L6
8019db00: ffffffff 801688b8 801688c8
8019db0c: ffffffff 801689c6 801689d6
```

| TryLevel | PreviousTryLevel | Filter | HandlerBlock |
|----------|-----------------|--------|--------------|
| 0 | `0xffffffff` (-1) | `0x801688b8` | `0x801688c8` |
| 1 | `0xffffffff` (-1) | `0x801689c6` | `0x801689d6` |

- **`PreviousTryLevel = -1`** en ambos: son bloques independientes (no anidados).
- **Filter**: función que evalúa la excepción. Si devuelve `1` (`EXCEPTION_EXECUTE_HANDLER`) → ejecutar el handler.
- **HandlerBlock**: código del `__except { }` que se ejecuta si el filter lo aprueba.
- **TryLevel = 0** activa el try#0; **TryLevel = -1** indica que no hay try activo.

`_except_handler2` capturado en i386kd (el dispatcher de excepciones del runtime MSVC):

![i386kd mostrando el prologue de _except_handler2](img/iocreatefile-kd-except-handler2.png)

---

## 5. Flujo del else — rama UserMode

Cuando `RequestorMode == UserMode` (≠ `'\0'`), la función debe validar que todos los punteros que recibió de usermode son realmente escribibles antes de usarlos.

```c
else {
    local_54 = (undefined4 *)0x0;

    /* Abrimos el Try — TryLevel = 0 */
    local_3c[3] = 0;
    local_2c = &stack0xfffffffc;
    local_14 = &stack0xffffff78;

    ProbeAndWriteHandle(FileHandle, 0);   /* pre-zerea *FileHandle y valida el puntero */

    ProbeForWrite(IoStatusBlock, 8, 4);   /* valida que IoStatusBlock sea escribible (8 bytes, alineado a 4) */

    /* Si no pasaron AllocationSize → crear uno en cero */
    if (AllocationSize == (PLARGE_INTEGER)0x0) {
        local_24 = (_struct_3)RtlConvertLongToLargeInteger(0);
    }
    else {
        ProbeForRead(AllocationSize, 8, 4);   /* valida que AllocationSize sea legible (8 bytes, alineado a 4) */
        local_24 = AllocationSize->field0;    /* copia el valor a memoria del kernel */
    }
```

![Ghidra mostrando el bloque UserMode con ProbeAndWriteHandle y ProbeForWrite](img/iocreatefile-ghidra-usermode-probe-block.png)

Vista completa del bloque, con las cuatro funciones ya renombradas en el proyecto Ghidra y el panel de Listing correlacionando la línea 89 (`ProbeForWrite`) con su dirección real:

![Ghidra mostrando el bloque completo del if/else de AllocationSize, con ProbeAndWriteHandle, ProbeForWrite, RtlConvertLongToLargeInteger y ProbeForRead ya renombradas](img/iocreatefile-ghidra-allocationsize-branch.png)
![Ghidra mostrando el código con los cuatro nombres reales aplicados: ProbeAndWriteHandle, ProbeForWrite, RtlConvertLongToLargeInteger, ProbeForRead](img/iocreatefile-ghidra-allocationsize-else-branch.png)

### ¿Qué hace `Probe` realmente?

Es clave no confundir esto: **`Probe` no copia nada, solo valida** — es un gate de permisos que corre *antes* de tocar la memoria. Para cada rango `[Address, Address+Length)` verifica tres cosas:

1. **Que la dirección caiga en espacio de usermode** (por debajo de `0x80000000` en este build) y no en espacio del kernel. Esto es lo central: el kernel corre con acceso total a *toda* la memoria, kernel y usuario. Sin este chequeo, un proceso podría pasar una dirección del kernel disfrazada de "mi handle de salida", y el kernel — que tiene permiso de sobra — terminaría escribiendo ahí a pedido de usermode. `Probe` es lo que bloquea ese primitivo de escalada de privilegios.
2. **Alineación** — el `4` que se repite en cada llamada, acorde al tipo que se está validando.
3. **Que la página esté presente y con el permiso correcto** (legible para `ProbeForRead`, escribible para `ProbeForWrite`) — si no lo está, ahí es donde salta `STATUS_ACCESS_VIOLATION`, capturado por el `__try/__except` de la Sección 4. El frame SEH existe *específicamente* para esto.

La copia a una variable local (`local_24 = AllocationSize->field0`, o el `*FileHandle = 0` de más abajo) es un paso **separado**, que hace `IoCreateFile` recién después de que `Probe` dio el visto bueno — es la defensa contra TOCTOU (*time-of-check to time-of-use*): otro hilo del mismo proceso podría modificar o desmapear esa memoria microsegundos después de validada, así que el valor se copia a memoria del kernel (fuera del alcance de usermode) una sola vez y el resto de la función ya no vuelve a tocar el puntero original.

### ProbeAndWriteHandle (`0x8010b760`)

Confirmado con `i386kd` — disassembly real:

```
NT!_ProbeAndWriteHandle:
8010b760  push    esi
8010b761  cmp byte ptr [NT!_MmCheckPteOnProbe], 0x0
8010b768  jz      +0x18
8010b76a  mov     esi, [esp+0x8]      ; esi = Address (FileHandle)
8010b76e  push    0x4                 ; alignment
8010b770  push    esi                 ; Address
8010b771  call    NT!_MmProbeForWrite ; valida escribibilidad
8010b776  jmp     +0x2f               ; → escribir el valor
```

Verifica que `MmCheckPteOnProbe` esté activo, llama a `MmProbeForWrite(Address, 4)` para garantizar que el puntero pertenece a usermode y es escribible, luego escribe `0` como valor inicial en `*FileHandle`.

### ProbeForWrite (`0x80113306`)

Llamada como `ProbeForWrite(IoStatusBlock, 8, 4)`:
- Puntero: `IoStatusBlock`
- Longitud: `8` bytes (tamaño de `IO_STATUS_BLOCK`)
- Alineación: `4` bytes

Valida que `IoStatusBlock` está completamente en espacio de usuario y es escribible.

**Por qué acá es solo `ProbeForWrite` y no `ProbeAndWrite` como con `FileHandle`:** `IoStatusBlock` es el resultado *final* de la operación (`Status`/`Information`) — algo que en este punto de la función todavía no existe. El valor real recién se conoce mucho más adelante, adentro de `IopCreateFile`, después de que el filesystem driver completa el IRP (potencialmente de forma asíncrona). El trabajo se divide en dos: **validar ya** (fail-fast — mejor descubrir un puntero inválido acá, con un error simple, que mil líneas después en medio de una IRP ya en curso) y **escribir después**, cuando el resultado real esté disponible.

### RtlConvertLongToLargeInteger (`0x80160084`)

Cuando `AllocationSize == NULL`, la función crea un `LARGE_INTEGER` de valor cero para usar como tamaño por defecto. `RtlConvertLongToLargeInteger(0)` extiende el entero `0` a 64 bits.

Confirmado en vivo con un breakpoint en `IoCreateFile+0x84`: el `jz` salta directo al `push 0x0` + `call NT!_RtlConvertLongToLargeInteger`, saltándose por completo la rama de `ProbeForRead` — la prueba de que cuando `AllocationSize` es `NULL` nunca se toca memoria de usermode para este parámetro:

![i386kd con breakpoint en IoCreateFile+0x84 mostrando el salto directo a RtlConvertLongToLargeInteger cuando AllocationSize es NULL](img/iocreatefile-kd-allocationsize-null-confirmed.png)

### ProbeForRead (`0x801136c6`)

Rama `else` — cuando el caller sí mandó un `AllocationSize` real (`!= NULL`):

```c
ProbeForRead(AllocationSize, 8, 4);
local_24 = AllocationSize->field0;
```

Mismo patrón que `ProbeForWrite`, pero para **lectura**: valida que los 8 bytes de `AllocationSize` son legibles desde usermode antes de desreferenciarlos. Recién con el puntero validado, `local_24 = AllocationSize->field0` copia el valor a la variable local del kernel — la misma defensa TOCTOU explicada arriba: se lee una sola vez, apenas validado, y el resto de la función ya no vuelve a tocar `AllocationSize` directamente.

---

## 6. Flujo completo de IoCreateFile

```
IoCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
             AllocationSize, FileAttributes, ShareAccess, Disposition,
             CreateOptions, EaBuffer, EaLength, CreateFileType,
             ExtraCreateParameters, Options)
│
├─ 1. Leer KTHREAD->PreviousMode desde FS:[0x124]+0x1d4
│     Si Options & 0x100 (IO_NO_PARAMETER_CHECKING) → forzar KernelMode
│
├─ 2. Si KernelMode → sin validaciones (el kernel se fía de sí mismo)
│
└─ 3. Si UserMode:
      ├─ Abrir try#0 (TryLevel = 0)
      ├─ ProbeAndWriteHandle(FileHandle, 0)     → pre-zerear + validar
      ├─ ProbeForWrite(IoStatusBlock, 8, 4)     → validar IoStatusBlock
      ├─ Si AllocationSize == NULL → RtlConvertLongToLargeInteger(0)
      │  Si no  → ProbeForRead(AllocationSize, 8, 4) + copiar a local_24
      ├─ Si EaBuffer != NULL:
      │   └─ Abrir try#1 (TryLevel = 1)
      │       ProbeForRead(EaBuffer, EaLength) + copiar al kernel heap
      └─ Llamar IopCreateFile(...)  ← el trabajo real
```

**Idea central:** `IoCreateFile` es un guardia de seguridad. Valida que los punteros de usermode son legítimos antes de pasarlos al motor real (`IopCreateFile`), todo protegido con `__try/__except` para capturar cualquier acceso inválido.

---

## 7. Flags internos (parámetro `Options`)

Definidos en `NTDDK.H` (DDK octubre 1994):

```c
#define IO_FORCE_ACCESS_CHECK    0x0001
#define IO_OPEN_PAGING_FILE      0x0002
#define IO_OPEN_TARGET_DIRECTORY 0x0004
// 0x0100 = IO_NO_PARAMETER_CHECKING (interno, no declarado públicamente)
```

El flag `0x100` es el único que afecta el flujo de `IoCreateFile` directamente: fuerza `KernelMode` saltando todas las validaciones de usermode.

---

## Referencias

- NT DDK octubre 1994 — `ddk_extract/INC/NTDDK.H`
- `ntoskrnl.exe` build 3.10.5098.1 — base `0x80100000`
- Ghidra 11 — Data Type Manager, Parse C Source
- `i386kd` — debugger kernel NT 3.1
