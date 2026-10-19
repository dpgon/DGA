# DGA: arquitectura (tal como está)

> Este documento describe la arquitectura **real** tras la puesta a punto de 2026 (fases 1–5 de `TODO.md`,
> commit `96e4046`), no la deseable. La primera versión describía el commit `269b362` (2021-08-12); lo que
> cambió desde entonces se indica como «En 2021». Las fuentes son el código, `docs/ESTUDIO.md`, las
> ejecuciones de `docs/MVP.md`, el diseño de `docs/CORRECCIONES.md` y lo que contó el autor. Cuando el motivo
> de una decisión no consta en ningún sitio, se dice: «motivo no documentado».

---

## 1. Visión general

DGA es un conjunto de **scripts de Python sin empaquetar** que comparten un paquete de generadores y se
comunican **solo a través de ficheros y de la salida estándar**. No hay procesos de larga duración,
servidor, base de datos ni configuración externa.

```
                       ┌────────────────────────────┐
                       │  DGAs/  (50 módulos)       │  cada uno: class DGA + get_domain()
                       │  DGAs/wordlist/ (datos)    │  ← 3 módulos leen diccionarios
                       └─────────────▲──────────────┘
                                     │ from DGAs import *  +  eval(nombre)
                       ┌─────────────┴──────────────┐
                       │  dga.py  (fachada)         │  info, detect, generate, create, bruteforce
                       └──▲──────────▲──────────▲───┘
                          │          │          │  import dga
        ┌─────────────────┴┐  ┌──────┴────────┐ ┌┴────────────────────────┐
        │ lookdga.py (CLI) │  │ statsdga.py   │ │ detectdga.py (CLI)      │
        │ solo stdlib      │  │ menú input()  │ │ features + RF + checks  │
        └────────┬─────────┘  └──────┬────────┘ └──┬───────────▲──────────┘
                 │ stdout -C         │ ngram.py    │ skops/csv  │ skops/csv + SHA-256
                 ▼                   │ nlpdata.py  ▼            │
        ml-data/2026/mydgas.dom ─────┼──────► ml-data/*.skops, *.json, tranco.ng1-4.csv
                                     │             ▲
        ml-data/tranco.csv, 2026/tranco-*.dom, dga.dom, hf-dga.dom, umbrella-raw.csv
        DGAs/wordlist/effective_tld_names.dat (en git)
                                     ▲
        fetchdata.py (solo stdlib) ──┘  descarga y verifica lo que lista ml-data/MANIFEST
                                         (releases de GitHub o la fuente original)

        Red: solo fetchdata.py, en la instalación. Ningún script descarga nada al ejecutarse.
```

**Las piezas se comunican así:**

- **Las tres CLI importan `dga.py` como biblioteca.** `dga.py` alcanza cada generador como nombre global
  y lo resuelve con `eval(nombre)` (`dga.py:20-37` y siguientes).
- **`detectdga.py` y `statsdga.py` importan `ngram.py`** y `nlpdata.py`, que comprueba que esté el corpus
  `brown` de NLTK sin descargarlo.
- **`fetchdata.py` es independiente:** solo usa la biblioteca estándar, lee `ml-data/MANIFEST` e instala los
  datos y el modelo. `detectdga.py` importa de él `sha256()` y `readmanifest()`.
- **Entre ejecuciones, los datos pasan por ficheros:** `lookdga.py -C` escribe el CSV en la salida estándar y
  las líneas de estado en la de error (C13); el usuario redirige la estándar a `ml-data/…/mydgas.dom`.
  `detectdga.py` escribe y lee en `ml-data/` conjuntos (`.pkl`, `.json`), modelos (`.skops`, `.json`) y el
  diccionario (`.csv`).
- **El orden de ejecución del entrenamiento lo impone el usuario** siguiendo el README
  (`--ngram → --main → --train → --secondary/--umbrella → --test_*`). El código comprueba que existan los
  ficheros que necesita y, al cargar un modelo o evaluarlo, que los hashes de lo que usa coincidan con sus
  metadatos.

---

## 2. Stack tecnológico

**Lenguaje:** Python **3.12 o 3.13** (`requirements.txt` exige pandas 3, que pide 3.11 o superior; se prueba con
3.12 y 3.13). `lookdga.py`, `dga.py`, `DGAs/` y `fetchdata.py` solo usan la biblioteca estándar.

**Dependencias** (`requirements.txt`, mínimas, validadas en el sondeo de `docs/CORRECCIONES.md`):

| Paquete | Mínima | Para qué está |
|---|---|---|
| scikit-learn | 1.9.1 | `RandomForestClassifier`, `StandardScaler`, `MinMaxScaler`, `train_test_split`, métricas |
| skops | 0.16.0 | Guardar y cargar modelos y escaladores sin pickle |
| pandas | 3.0.6 | DataFrames de características (los conjuntos intermedios se guardan con `to_pickle`) |
| numpy | 2.5.4 | Entropía, Gini, estadísticos de n-gramas |
| nltk | 3.10.3 | `LegalitySyllableTokenizer` + corpus `brown` para las sílabas |

`requirements-lock.txt` fija todas las versiones, transitivas incluidas
(`uv pip compile requirements.txt --universal --python-version 3.12`). `requirements-dev.txt` añade
`pytest` 9.1.1.

**Biblioteca estándar relevante:**
- `argparse` para las CLI;
- `csv` para el diccionario de n-gramas, `json` para los metadatos;
- `hashlib`, `urllib.request` y `zipfile` en `fetchdata.py`;
- `re` para los patrones;
- `datetime`;
- `binascii.crc32` para la característica de TLD;
- `ctypes` (`c_uint`/`c_int`) para emular aritmética de 32 bits en 7 generadores;
- `hashlib`, `struct`, `base64` e `itertools` en los generadores.

**Herramientas:** `pytest`; GitHub Actions (`.github/workflows/tests.yml`), comprobado en local con `act`;
`uv` para generar el lock. No hay linters ni formateadores configurados.

**En 2021:** `requirements.txt` era un `pip freeze` de 14 paquetes con versiones exactas (scikit-learn 0.24.2,
pandas 1.3.1, numpy 1.21.1, nltk 3.6.2, `dnspython` 2.1.0 para código muerto y nueve transitivas), que solo se
instalaba en Python 3.9 x86_64. Persistía con `pickle`.

---

## 3. Estructura del proyecto

```
DGA/
├── lookdga.py          CLI del catálogo: -L -I -G -C -D -B -F (112 líneas, solo stdlib)
├── dga.py              Fachada sobre DGAs/: info, detect, bruteforce, listall, generate, create (287 l.)
├── detectdga.py        ML completo: sufijos, features, conjuntos, entrenamiento, evaluación, --check (1.014 l.)
├── ngram.py            Clase ngrams: contar 1-4-gramas, normalizar, consultar, guardar/cargar en CSV (117 l.)
├── statsdga.py         Menú interactivo de estadísticas; se ejecuta al importarse (576 l.)
├── fetchdata.py        Descarga y verifica los datos de ml-data/MANIFEST (222 l., solo stdlib)
├── nlpdata.py          Comprueba que está el corpus brown de NLTK, sin descargarlo (16 l.)
├── requirements.txt    Dependencias directas con versión mínima
├── requirements-lock.txt  Versiones exactas (uv pip compile)
├── requirements-dev.txt   pytest
├── pytest.ini          Marcadores slow y model; por defecto sin las lentas
├── DGAs/
│   ├── __init__.py     __all__ con los 50 nombres cortos: es el registro de familias
│   ├── <familia>.py    50 módulos; uno por variante (locky2, locky3…)
│   └── wordlist/       words1-3.txt (suppobox), luther/rfc4343/nasa/gpl (gozi), words.json (nymaim2),
│                       effective_tld_names.dat (lista de sufijos de Mozilla, 2026-10-17)
├── ml-data/            En git solo MANIFEST; el resto lo instala fetchdata.py (ver §4)
├── tests/              Pruebas pytest, conftest.py y data/ (instantánea de generadores, referencia Netlab)
├── .github/workflows/  tests.yml: matriz {Ubuntu, macOS 14, Windows} × {3.12, 3.13}
├── release/            Borradores locales de las releases data-2026 y model-2026 (ignorado por git)
├── yara/               35 reglas de Malpedia (junio 2021); no las lee ningún código
├── .idea/              Proyecto PyCharm; versionado aunque .gitignore lo excluye
├── LICENSE             GPL v2
└── docs/               Documentación de la puesta a punto (2026)
```

**Para orientarse:**
- Cambiar o añadir una familia: `DGAs/<familia>.py` y su nombre en `DGAs/__init__.py`.
- Cambiar cómo se reconoce o atribuye un dominio: `dga.py:110-193`.
- Cambiar el modelo: `detectdga.py`. Las características se calculan en un único sitio, `domainfeatures()`
  (`detectdga.py:794`), en el orden de `COLUMNS` (`:58`). Las usan `createmaindataset()`, `datasetrows()`
  (conjuntos de evaluación) y `classify()` (`--check`).
- Cambiar qué datos se usan: `ml-data/MANIFEST` y las constantes `TRAINING`, `SECONDARY`, `UMBRELLA` y
  `ETLDS` de `detectdga.py:33-53`.

---

## 4. Modelo de datos

No hay motor de almacenamiento ni migraciones. Todo son **ficheros en disco**, con rutas relativas
escritas en el código, y el «esquema» está en ese mismo código.

### 4.1 Entidades

| Entidad | Dónde vive | Estructura real |
|---|---|---|
| **Familia/variante** | `DGAs/<nombre>.py`, clase `DGA` | Atributos de clase: `shortname, name, ref[], desc, yara, samples (int, 0 = sin tope), lcg, use_date (False o nº de días), use_seed (texto), configs[] (semillas; [None] si no hay), variation, regex, ends[]`. Instancia: `DGA(date=datetime, seed=str)`; `get_domain() → str` |
| **Registro de familias** | `DGAs/__init__.py` | Lista `__all__`; el orden es el de `-L` |
| **Manifiesto de datos** | `ml-data/MANIFEST` (en git) | TSV con cabecera `file url size sha256 source license set`. `url` es una URL, `URL#miembro` (un fichero de un zip) o `lines:FUENTE:PRIMERA-ÚLTIMA` (derivado de otro fichero, como el `sed` + `cut` del README). `set` es `2021`, `2026` o ambos |
| **Juego de datos** | columna `set` del manifiesto | `2026` (por defecto): modelo y datos actuales, en `ml-data/` y `ml-data/2026/`. `2021`: los del máster (release `v2021`), con los nombres de entonces en `ml-data/` |
| **Dominio etiquetado (corpus)** | stdout de `-C` → `ml-data/2026/mydgas.dom` | CSV sin cabecera `dominio,familia,config,AAAA-MM-DD`. El de 2021 (`ml-data/mydgas.dom`) tiene líneas `* …` con ANSI intercaladas |
| **Feed DGA externo** | `ml-data/dga.dom` | TSV de 360 Netlab `familia\tdominio\tinicio\tfin`, comentarios `#` (copia de 2021, en los dos juegos) |
| **DGA de Hugging Face** | `ml-data/hf-dga.dom` | `familia\tdominio`, comentarios `#` |
| **Listas de dominios legítimos** | `ml-data/tranco.csv` (`rango,dominio`) → `ml-data/2026/tranco-{main,test2,ngram}.dom`; `ml-data/umbrella-raw.csv` | Un dominio por línea; Umbrella en `rango,nombre` (con subdominios) |
| **Diccionario de n-gramas** | `ml-data/tranco.ng1.csv` … `ng4.csv` | CSV con cabecera `ngram,value`; valor ∈ [0,1] (MinMax por orden n), escrito con `repr()` para que no pierda precisión |
| **Conjunto de características** | `ml-data/{main,secondary,umbrella}.pkl` (locales, no se publican) | Pickle de DataFrame con las 28 columnas de `COLUMNS`: `sld, tld, family, dga(0/1)` y las 24 características |
| **Informe del conjunto** | `ml-data/{main,secondary,umbrella}.json` | Juego, fecha, ficheros de entrada con SHA‑256 y fuente, SHA‑256 del diccionario y de la lista de sufijos; en los de evaluación, los datos de entrenamiento excluidos y los recuentos leídos/no evaluables/excluidos/conservados por origen |
| **Modelo** | `ml-data/{variante}.skops` | `RandomForestClassifier` guardado con skops |
| **Escalador** | `ml-data/{variante}-scaler.skops` | `StandardScaler` guardado con skops |
| **Metadatos del modelo** | `ml-data/{variante}.json` | Versiones de Python y librerías, fecha, juego, ficheros de entrada con SHA‑256 y fuente (incluye el ID de Tranco), SHA‑256 del diccionario, de la lista de sufijos, del modelo y del escalador, características, hiperparámetros, tiempo de entrenamiento, métricas de la partición de prueba y `evaluations` (métricas y recuentos de `--test_*`) |
| **Sufijos efectivos** | `DGAs/wordlist/effective_tld_names.dat` + 154 literales en `loadetlds()` | Lista `etlds` y conjunto `etldset` (búsquedas rápidas) |

**En 2021:** el diccionario y los modelos eran pickles (`tranco.ng1..ng4`, `full.pkl`, `full-scaler.pkl`),
versionados en git junto con las listas, sin manifiesto ni hashes.

### 4.2 Relaciones y contratos

- **Las variantes del modelo dependen del orden de las columnas.** Una variante es «conjunto principal menos
  ciertas columnas» (`traindata()` y `evaluate()`). `X = df.iloc[:, 1:]` supone que `dga` es la primera
  columna tras quitar `sld/tld/family`. Los metadatos guardan la lista de características y la prueba de
  paridad (`tests/test_model.py`) comprueba que `--check` calcula lo mismo que `--main`.
- **Modelo, escalador, diccionario y lista de sufijos van juntos.** Los metadatos guardan sus SHA‑256, y
  `loadmodel()` (`detectdga.py:661`) se niega a cargar el modelo si alguno no coincide, diciendo cuál.
- **Un conjunto de evaluación va con un modelo.** `testsecdata()` rechaza un conjunto construido con otro
  diccionario, otra lista de sufijos u otros datos de entrenamiento que los del modelo.
- **Ningún conjunto de evaluación comparte dominio ni SLD con el entrenamiento** de su juego (`trainingdata()`
  y `datasetrows()`, C5).
- **Cada fichero instalado debe coincidir con el manifiesto.** `fetchdata.py` borra lo que no coincide y no
  sobrescribe un fichero local distinto.

### 4.3 Cómo se «migra»

No se migra: cualquier cambio de características obliga a regenerar `main.pkl` y a reentrenar. skops no
ejecuta código al cargar, pero **no garantiza que un modelo cargue en otra versión de scikit-learn**: subir de
versión obliga a comprobarlo y, si no, a reentrenar. Un modelo nuevo es un fichero nuevo en el manifiesto y
una release nueva; no se cambia el hash de un fichero publicado.

---

## 5. Interfaces y contratos

### 5.1 CLI (la única interfaz pública)

| Orden | Opciones | Contrato de salida |
|---|---|---|
| `lookdga.py` | grupo excluyente `-L -I -G -C -D -B -F`; `-d AAAA-MM-DD`, `-n N` (10), `-m familia…`, `-s semilla`, `-b días` (366) | Texto libre con colores ANSI; `-C`, CSV en la salida estándar y estado en la de error |
| `detectdga.py` | `--ngram`, `--main`, `--secondary`, `--umbrella`, `--set {2021,2026}`, `--train V`, `--test_secondary V`, `--test_umbrella V`, `--check dom…`, `-b`; `--alexa` y `--test_alexa`, alias obsoletos | Texto libre con colores ANSI; mensajes de error en la de error. **No son excluyentes:** si se pasan varias, gana la primera de la cadena `if/elif` de `main()` |
| `statsdga.py` | ninguna; menú `input()` 0-9 | Texto libre |
| `fetchdata.py` | `--set` (2026), `--from DIR`, `--nltk`, `--manifest`, `--root` | Una línea por fichero; código 1 si alguno no se instala |

**Códigos de salida:** `detectdga.py`, `statsdga.py` y `fetchdata.py` terminan con código 1 cuando falta un
fichero, no coincide un hash o falla una descarga. `lookdga.py` sigue terminando los errores de usuario con
`exit()`, es decir, código 0 (`lookdga.py:55,74,84`).

### 5.2 Fronteras entre módulos

- **Generador ↔ fachada.** Contrato por nombres de atributo, con *duck typing* y sin clase base. La fachada
  da por hecho que todo módulo listado en `__all__` define `DGA` con todos los atributos. Además, como usa
  `eval(nombre)`, el nombre del módulo debe coincidir con el nombre global importado.
- **Fachada ↔ CLI.** Las funciones de `dga.py` tienen un parámetro `main` que decide si **imprimen o
  devuelven** el resultado. Es la misma función con dos contratos. `detect()` fuerza además `brute=True`
  cuando `main=False`.
- **`ngram.py` ↔ `detectdga.py`.** `getall(domain, n)` devuelve `(media, mediana, desviación)` del primer
  label, o `(None, None, None)` si mide 3 caracteres o menos. `detectdga.py` filtra antes con `sldtld()` y
  nunca llega a ver los `None`.
- **`fetchdata.py` ↔ `detectdga.py`.** `detectdga.py` usa `sha256()` y `readmanifest()` para los metadatos;
  `fetchdata.py` no importa nada del proyecto.
- **Duplicaciones entre módulos:** `Col` (colores) está definida en `lookdga.py`, `dga.py` y `fetchdata.py`.
  Las cuentas de vocales y consonantes existen dos veces con criterios distintos: `vcn()` (`detectdga.py`,
  divide por la longitud) y `vcrel()` (`statsdga.py`, divide por vocales + consonantes). Las letras dobles y
  repetidas también están dos veces.

### 5.3 Red

- **Saliente, solo en la instalación:** `fetchdata.py` descarga los ficheros del manifiesto (releases de
  GitHub, Tranco, Cisco Umbrella, la etiqueta `v2021`) y, con `--nltk`, el corpus `brown`. Comprueba el
  SHA‑256 de todo lo que descarga.
- **Al ejecutar:** ninguna. Si falta el corpus, `nlpdata.requirebrown()` detiene el script con el comando que
  lo instala; si falta un fichero, el mensaje remite a `fetchdata.py`. Lo comprueba `tests/test_offline.py`.
- **Preparada y no usada:** consultas DNS de hasta 60 tipos de registro (`existdomain()`, código muerto; su
  `import` de `dnspython` está dentro de la función y `dnspython` ya no es dependencia).
- **Entrante:** ninguna.
- **En 2021:** `nltk.download('brown')` se ejecutaba al importar `detectdga.py` y `statsdga.py`, sin
  confirmación, y los datos venían con el clon.

---

## 6. Aspectos transversales

- **Configuración:** no hay fichero, variables de entorno ni opciones de rutas. Todo está en el código:
  - rutas relativas al directorio de trabajo (`"ml-data/…"`, `"DGAs/wordlist/…"`), así que **hay que lanzarlo
    desde la raíz del repositorio**;
  - qué ficheros forman cada juego: `TRAINING`, `SECONDARY`, `UMBRELLA` (`detectdga.py:33-53`);
  - hiperparámetros en `HYPERPARAMETERS` (`n_estimators=30`, `min_samples_leaf=5`, `random_state=1`,
    `n_jobs=-1`, `detectdga.py:56`) y la partición `test_size=0.2`, `random_state=100`;
  - 10 posiciones de fuerza bruta en `--check` (`detectdga.py:900`).
- **Gestión de errores:** el código nuevo captura excepciones concretas y termina con un mensaje y código 1
  (`requirefiles()`, `loadmodel()`, `fetchdata.py`). Quedan `except:` desnudos en el código antiguo:
  - `lookdga.py:52,70,81`;
  - `dga.py:228` (fallo de un generador ignorado);
  - `detectdga.py:178` (código muerto) y `:311` (`createngram()`);
  - `statsdga.py:575`, que convierte cualquier excepción en «Incorrect option».
- **Logging y observabilidad:** solo `print` con colores ANSI (clase `Col`), barras de progreso hechas con
  `=` cada 100.000 líneas y el `verbose=1` de scikit-learn al entrenar. Los conjuntos y los modelos dejan su
  informe en `.json`.
- **Concurrencia:** solo la interna de scikit-learn (`n_jobs=-1` al entrenar y al cargar: todos los núcleos de
  la máquina). La fuerza bruta es secuencial. No hay trabajos en segundo plano.
- **Estado global:** `etlds` (lista) y `etldset` (conjunto) se rellenan una vez por lista de sufijos
  (`loadetlds()`); las búsquedas usan el conjunto.
- **Internacionalización:** no hay. La interfaz está en inglés, con restos en español (`statsdga.py`: «Rango
  tipico»). Los IDN se tratan solo en su forma `xn--`.
- **Portabilidad:** las rutas usan `/` (Python lo acepta en Windows). Siete generadores usan `ctypes`
  para enteros de 32 bits, lo cual es portable. pykspa2 y suppobox dependen de la zona horaria de la máquina
  (`time.mktime`); las pruebas fijan `TZ=UTC`, pero en Windows `time.tzset()` no existe. Windows **no se ha
  verificado** (fase 7 de `TODO.md`).

---

## 7. Seguridad

Descripción del estado actual; la auditoría es un paso aparte.

- **Autenticación, autorización y secretos:** no aplican. Herramienta local sin usuarios ni credenciales;
  no hay secretos en el repositorio (revisión visual del árbol, no de todos los ficheros de datos).
- **Carga de modelos:** con skops (`loadmodel()`), que no ejecuta código al cargar y solo acepta los tipos que
  conoce más los de `TRUSTED` (`detectdga.py:54`): `sklearn.tree._tree.Tree`. Ese tipo está en la lista
  porque un fichero malicioso puede llevar índices de nodo fuera de rango, que al predecir pueden leer fuera
  de memoria o cerrar el proceso. Se acepta porque los modelos los genera el proyecto y su SHA‑256 está fijado
  en el manifiesto, que vive en git. Un tipo desconocido se rechaza con un mensaje.
- **Pickles que quedan:** los conjuntos intermedios `main.pkl`, `secondary.pkl` y `umbrella.pkl` se guardan y
  cargan con pandas. Los genera cada usuario en su máquina y no se publican. Las pruebas cargan los pickles
  de 2021 (`tranco.ng*`) solo para comprobar la conversión del diccionario, y su hash lo fija el manifiesto.
- **Integridad de los datos:** `fetchdata.py` comprueba tamaño y SHA‑256 de todo lo que instala; la integridad
  depende del manifiesto, que está en git.
- **`eval` con datos derivados de la entrada:**
  - `lookdga.py:68`: `eval(f"dga.{item}")` con el argumento `-m`. Lo controla quien ejecuta la orden;
    el riesgo es bajo.
  - `dga.py`: `eval(nombre)` sobre nombres de `__all__`, que son fijos.
  - **En 2021** había otro en `ngram.py`, con el n-grama del dominio analizado; desapareció al pasar el
    diccionario a CSV (fase 5).
- **Validación de entradas:** mínima. Las fechas se validan (`lookdga.py:49-55`). Los dominios se pasan a
  minúsculas, y los que no se pueden evaluar se listan con el motivo (C12).
- **Red:** solo en la instalación (§5.3), con verificación de hashes. Las consultas DNS muertas filtrarían a
  la red los dominios analizados si alguien las reactivara.
- **Material de malware:** el repositorio no contiene binarios. Las reglas YARA son texto. Los generadores
  solo producen nombres de dominio.
- **Cadena de suministro:** dependencias actuales con versión mínima; el lock fija las exactas. Las releases y
  las fuentes de datos externas (Tranco, Umbrella, Hugging Face) se verifican por hash.

---

## 8. Estrategia de pruebas

**Comandos** (desde la raíz, con el corpus `brown` en `NLTK_DATA`):

```bash
pip install -r requirements-dev.txt
pytest              # por defecto, sin las lentas (unos 70 s en Apple Silicon)
pytest -m slow      # las lentas (más de 30 s cada una)
```

**Marcadores:** `slow` y `model` (necesita el modelo y el diccionario; sin ellos, la prueba se salta).
Las pruebas que necesitan datos o el corpus se saltan si faltan; ninguna descarga nada. Se ejecutan en UTC
(`tests/conftest.py`).

**Qué cubren:**

| Tipo | Ficheros |
|---|---|
| Caracterización (lo verificado en `docs/MVP.md`; si fallan, se ha roto algo que funcionaba) | `test_lookdga.py`, `test_generators.py` (instantánea de los 50 generadores y referencia de Netlab), `test_check.py`, `test_statsdga.py` |
| Correcciones de `docs/CORRECCIONES.md` | `test_offline.py` (C11), `test_cli.py` (C6, C9), `test_datasets.py` (C3, C5), `test_sldtld.py` (C7), `test_fetchdata.py` (C8), `test_ngram.py` y `test_model.py` (C2, C10; incluye la paridad de características) |
| Datos instalados frente al manifiesto | `test_data.py` (`slow`) |

**CI:** `.github/workflows/tests.yml`, matriz {`ubuntu-latest`, `macos-14`, `windows-latest`} × {3.12, 3.13}:
instala el lock, ejecuta `fetchdata.py --nltk` con caché y `pytest`. Comprobada en local en Linux (`act`) y
en macOS Apple Silicon; en GitHub no se ejecutará hasta la publicación (fase 7), y Windows está sin verificar.

**Sin cubrir:**
- 39 de 50 generadores, sin confirmación externa;
- las variantes del modelo distintas de `full` y `tiny`;
- la opción 3 de estadísticas y la 9;
- la mayoría de las rutas de error de `lookdga.py` y `statsdga.py`.

**En 2021** no había ninguna prueba ni CI.

---

## 9. Compilación, CI y despliegue

- **Compilación:** no hay. Son scripts interpretados.
- **Distribución:** **clonar el repositorio de GitHub** (`git@github.com:dpgon/DGA.git`), que solo trae código y
  el manifiesto, y ejecutar `python fetchdata.py --nltk`. Los ficheros grandes son assets de release:
  - `v2021`: los datos y el modelo del máster (publicada);
  - `data-2026`: los datos de 2026 que se pueden redistribuir (lista de sufijos, Hugging Face, corpus propio);
  - `model-2026`: el modelo actual, su escalador, sus metadatos y el diccionario.

  Tranco y Umbrella se descargan de su origen, porque no está claro que se puedan redistribuir. **`data-2026` y
  `model-2026` están preparadas en `release/` y se publican en la fase 7**; hasta entonces, `fetchdata.py
  --from release/…` las instala desde el disco. No hay paquete en PyPI, ni `pyproject.toml`, ni imagen de
  contenedor.
- **Instalación:** `pip install -r requirements-lock.txt` en Python 3.12 o 3.13, y `python fetchdata.py
  --nltk`.
- **Ejecución:** `python <script>.py …` **desde la raíz del repositorio**.
- **CI:** ver §8.
- **Actualización:** `git pull` y `python fetchdata.py`. Un modelo nuevo es una release nueva y entradas
  nuevas en el manifiesto.
- **Límite de la plataforma:** ninguno en la práctica: los assets de release admiten hasta 2 GB, y
  `full.skops` pesa 110 MB.
- **En 2021:** los 367 MB de `ml-data/` iban en git y `full.pkl` (99,9 MB) estaba a unos 100 KB del límite de
  GitHub; la instalación documentada no funcionaba en sistemas actuales.

---

## 10. Objetivos de rendimiento

El proyecto **no declara ninguno**. Cifras medidas en macOS Apple Silicon, nativo, con 12 núcleos (entre
paréntesis, las de 2021 bajo emulación x86_64):

| Operación | Medida |
|---|---|
| `detectdga.py --check` con 5 dominios | 3,7 s en total, incluida la carga (27 s) |
| `detectdga.py -b --check` con 5 dominios | 58 s (1 min 51 s) |
| `lookdga.py -B` con 2 dominios (366 días × 10 posiciones) | 1 min 45 s (4 min 11 s) |
| `--ngram` (2,6 M de dominios) | 19 s |
| `--main` (2,9 M de dominios) | 5 min 40 s |
| `--secondary` (2,6 M leídos) | 3 min 54 s (34 min) |
| `--umbrella` | 23 s (2 min) |
| `--train full` / `tiny` | 33 s / 9 s |
| `pytest` por defecto / con las lentas | unos 70 s / unos 3 min 20 s |

**Tamaños:** modelo `full`, 110 MB; `tiny`, 67 MB; diccionario de 4-gramas, 15,8 MB; `dga.dom`, 99 MB.

**Las cifras que importarían en este producto** son el tiempo por dominio en `--check` (para listas
grandes, ver `docs/FUTURE.md` 1.2.5) y el coste de la fuerza bruta por familia candidata.

---

## 11. Registro de decisiones

**D** = documentado (README, commit o `docs/CORRECCIONES.md`) · **C** = deducido del código o de los ficheros ·
**U** = contado por el usuario

**Decisiones de 2021:**

| Decisión | Motivo | Cómo se sabe |
|---|---|---|
| Python 3, en Linux x86_64 con PyCharm | Entorno de trabajo del autor durante el máster | U; C (`.idea/misc.xml`) |
| Reimplementar los DGA a partir de Johannes Bader | Partir de implementaciones fiables y citadas | D (README) |
| Un módulo por variante con clase `DGA` y metadatos de clase | Facilita la fuerza bruta y la ficha genérica. El motivo concreto no está documentado | C |
| Registro por `__all__` + `from DGAs import *` + `eval` | Motivo no documentado; parece la vía más corta para iterar por nombre | C |
| Random Forest (`RandomForestClassifier`, 30 árboles) | Motivo no documentado. El autor lo describe como el núcleo del detector | U (propósito); C |
| N-gramas 1–4 sobre Tranco como característica principal | Medir cuánto se parece un SLD a los dominios humanos | U; C (`ngram.py`) |
| Tranco para entrenar y Alexa para probar | Tranco resiste mejor la manipulación (**suposición**); Alexa como segunda fuente independiente, aunque en realidad no lo era: solapamiento del 62 % | D (README, fuentes); C (solapamiento) |
| Feed de 360 Netlab como DGA de entrenamiento | Fuente pública de dominios DGA reales | D (README) |
| CRC32 del TLD como característica numérica | Motivo no documentado | C (`domainfeatures()`) |
| Variantes del modelo (`ngram`, `nosyll`, `tiny`…) | Estudio de ablación: ver qué aporta cada grupo de características | C (`traindata()`) |
| 10 posiciones y 366 días en la fuerza bruta | Motivo no documentado; acota el coste | C (`lookdga.py:23-25`, `detectdga.py:900`) |
| Reglas YARA incluidas sin uso | Motivo no documentado; material de referencia del estudio | D (README); C |
| Ignorar `.idea` tras haberlo versionado | **Accidental:** ignorarlo no lo saca del índice | C (commits `fde8bb0`, `269b362`) |

Decisiones de 2021 sustituidas en 2026: versionar datos y modelos en git, pickle como formato, `requirements.txt`
como `pip freeze`, `n_jobs=14`, el extractor de características copiado en varios sitios (accidental) y
`dnspython` para código muerto (accidental).

**Decisiones de la puesta a punto de 2026** (detalle en `docs/CORRECCIONES.md`, «Decisiones tomadas»):

| # | Decisión | Motivo | Cómo se sabe |
|---|---|---|---|
| D1 | Requisitos mínimos + `requirements-lock.txt`, Python 3.12/3.13 | Atacar la causa (el freeze) sin rediseñar el proyecto | D |
| D2 | Reentrenar y guardar con skops + metadatos; n-gramas en CSV | Quitar la dependencia de la estructura interna de scikit-learn y la ejecución de código al cargar | D |
| D3 | Entrenar con `dga.dom` de 2021 y evaluar con Hugging Face sin solapes; generadores propios solo como prueba. **Sin DGArchive** (decisión del autor, 2026-10-19) | Reproducible con datos abiertos; no hay circularidad | D |
| D4 | Tranco `467YX` para los tres conjuntos, Umbrella en lugar de Alexa, lista de sufijos actual, `statsdga.py` con Tranco | Datos de hoy, reproducibles por ID, con una prueba de fuente distinta | D |
| D5 | Datos y modelos como assets de release con SHA‑256 y un paso de descarga; solo se redistribuye lo que tiene licencia clara | Sin límite de tamaño, verificable, y sin conexión una vez instalado | D; U (licencias) |
| D6 | Incluir C11, C12 y C13 | Sin ellas, las comprobaciones del modelo nuevo podían mentir | D |
| D7 | Etiquetar `v2021` y sacar sus ficheros del árbol de trabajo | Un solo diseño de rutas; lo de 2021 sigue en la etiqueta y su release | D |
| — | Un único extractor de características, `domainfeatures()`, con prueba de paridad | Evitar el desfase silencioso entre entrenamiento y predicción | C; D (`TODO.md`) |
| — | Juego `2026` por defecto, `2021` como juego histórico | El modelo de 2021 solo carga en su entorno | D (`TODO.md`) |

---

## 12. Deuda y riesgos

| # | Riesgo / deuda | Dónde | Impacto | Estado |
|---|---|---|---|---|
| 1 | Dependencias de 2021 sin binarios en plataformas actuales | `requirements.txt` | No se instalaba en sistemas actuales | **Resuelto** (C1) |
| 2 | Modelos atados a scikit-learn 0.24.2 | `ml-data/*.pkl` | No cargaban en scikit-learn actual | **Resuelto** con el reentrenamiento (C2); skops tampoco garantiza la carga en otra versión (§4.3) |
| 3 | Deserializar pickles de un repositorio público | `detectdga.py`, `ngram.py` | Ejecución de código arbitrario si los ficheros se alteran | **Resuelto** (C2): skops con tipos de confianza; quedan pickles locales (§7) |
| 4 | Sin pruebas ni CI | — | Cualquier cambio podía romper un generador sin que nadie lo notara | **Resuelto en parte:** hay pruebas y CI; 39 de 50 generadores siguen sin confirmación externa |
| 5 | Desalineación de veredictos y descartes silenciosos | `classify()` | Resultados atribuidos al dominio equivocado | **Resuelto** (C12) |
| 6 | Extractor de características duplicado y columnas declaradas a mano | `detectdga.py` | Desfase silencioso entre entrenamiento y predicción | **Resuelto:** `domainfeatures()` y `COLUMNS`, con prueba de paridad |
| 7 | Contrato de generadores por *duck typing* + `eval` | `dga.py`, `DGAs/__init__.py` | Un atributo mal escrito solo falla en ejecución | Pendiente |
| 8 | Funciones con doble contrato (`main=True/False`) | `dga.py` | Mezclan presentación y lógica | Pendiente |
| 9 | `except:` desnudos | `dga.py:228`, `lookdga.py`, `detectdga.py:178,311` | Los errores reales desaparecen | Pendiente; el código nuevo no los usa |
| 10 | Patrones sin escapar ni anclar | `dga.py:117-125` | Falsos positivos masivos (`google.com` frente a 6 familias) | Pendiente (`docs/FUTURE.md` 1.1.4) |
| 11 | Rutas relativas al directorio actual | todos los scripts | Falla al ejecutarse desde otra carpeta | Pendiente |
| 12 | Descarga de red al importar | `detectdga.py`, `statsdga.py` | Rompía el requisito «sin conexión una vez instalado» | **Resuelto** (C11) |
| 13 | `statsdga.py` sin `if __name__ == "__main__"` | `statsdga.py:430` | No se puede importar; se prueba como script | Pendiente |
| 14 | 367 MB de datos en git; `full.pkl` al límite de GitHub | `ml-data/` | Clonado pesado | **Resuelto** (C8): assets de release; los ficheros siguen en el historial de git |
| 15 | Conjuntos de evaluación no independientes, y Alexa ya no existe | `ml-data/alexa.dom` | Métricas no fiables | **Resuelto** (C3, C5) |
| 16 | `n_jobs=14` fijo | `detectdga.py` | Sobresuscripción en otras máquinas | **Resuelto** (C10) |
| 17 | `.idea/` versionado pese al `.gitignore` | `.idea/` | Configuración personal publicada | Pendiente; lo decide el autor |
| 18 | Licencias mezcladas sin revisar | `LICENSE`, `yara/*.yar` | Riesgo de incompatibilidad al redistribuir | **En parte:** las de los datos están revisadas en el manifiesto; las de las reglas y los algoritmos, no |
| 19 | Sin datos DGA reales posteriores a 2021 | `dga.dom`, `hf-dga.dom` | Las métricas no miden el envejecimiento del modelo | Nuevo; `docs/FUTURE.md` 1.2.1 |
| 20 | Nombres aleatorios de CDN clasificados como DGA | modelo | 36,8 % de falsos positivos en el conjunto Umbrella | Nuevo; ver `docs/MVP.md` |
| 21 | Generadores que dependen de la zona horaria | `DGAs/pykspa2.py`, `suppobox.py` | La atribución puede cambiar según la máquina | Nuevo; `docs/CORRECCIONES.md`, anexo |
