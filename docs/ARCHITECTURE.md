# DGA: arquitectura (tal como está)

> Este documento describe la arquitectura **real** del commit `269b362` (2021-08-12), no la deseable. Las
> fuentes son el código, `docs/ESTUDIO.md`, las ejecuciones de `docs/MVP.md` y lo que contó el autor.
> Cuando el motivo de una decisión no consta en ningún sitio, se dice: «motivo no documentado».

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
                 │ stdout -C         │ usa ngram.py │ pickle     │ pickle
                 ▼                   │             ▼            │
        ml-data/mydgas.dom ──────────┼──────► ml-data/*.pkl, tranco.ng1-4 ─┘
                                     │             ▲
        ml-data/tranco-*.dom, dga.dom, alexa.dom ──┘   (descargados a mano)
        DGAs/wordlist/top-1m.csv, effective_tld_names.dat
                                     │
        Red: solo nltk.download('brown') al importar detectdga.py / statsdga.py
```

**Las piezas se comunican así:**

- **Las tres CLI importan `dga.py` como biblioteca.** `dga.py` alcanza cada generador como nombre global
  (`dga.py:2-4`) y lo resuelve con `eval(nombre)` (`dga.py:19,23,58,117,143…`).
- **`detectdga.py` y `statsdga.py` importan `ngram.py`** (`detectdga.py:11`, `statsdga.py:7`).
- **Entre ejecuciones, los datos pasan por ficheros:** `lookdga.py -C` escribe en la salida estándar y el
  usuario la redirige a `ml-data/mydgas.dom` (README). `detectdga.py` escribe y lee pickles en `ml-data/`.
- **El orden de ejecución del entrenamiento lo impone el usuario** siguiendo el README
  (`--ngram → --main → --train → --test_*`). El código solo comprueba que existan los ficheros que necesita
  (`detectdga.py:763-815`).

---

## 2. Stack tecnológico

**Lenguaje:** Python 3. Ningún manifiesto declara la versión. **Versión de facto: 3.9**
(`.idea/misc.xml`: «Python 3.9 (DGA)»), en **Linux x86_64 con PyCharm**, según el autor.

`requirements.txt`, versiones exactas:

| Paquete | Versión | Para qué está | Directa / transitiva |
|---|---|---|---|
| scikit-learn | 0.24.2 | `RandomForestClassifier`, `StandardScaler`, `MinMaxScaler`, `train_test_split`, métricas | directa (`detectdga.py:14-17`, `ngram.py:3`) |
| pandas | 1.3.1 | DataFrames de características y tablas de n-gramas, persistidos con `to_pickle` | directa |
| numpy | 1.21.1 | entropía, Gini, estadísticos de n-gramas | directa |
| nltk | 3.6.2 | `LegalitySyllableTokenizer` + corpus `brown` para las sílabas | directa |
| dnspython | 2.1.0 | `resolver.resolve` en `existdomain()`, **código muerto** | directa |
| scipy 1.7.1, joblib 1.0.1, threadpoolctl 2.2.0 | — | requeridas por scikit-learn | transitivas |
| click 8.0.1, regex 2021.8.3, tqdm 4.62.0 | — | requeridas por nltk | transitivas |
| python-dateutil 2.8.2, pytz 2021.1, six 1.16.0 | — | requeridas por pandas | transitivas |

**Biblioteca estándar relevante:**
- `argparse` para las CLI;
- `pickle` para modelos y escaladores;
- `re` para los patrones;
- `datetime`;
- `binascii.crc32` para la característica de TLD;
- `ctypes` (`c_uint`/`c_int`) para emular aritmética de 32 bits en 7 generadores;
- `hashlib`, `struct`, `base64` e `itertools` en los generadores.

**Forma del manifiesto:** es un `pip freeze`. Llegó en un commit aparte un día después (`269b362`), en
orden alfabético, con todas las transitivas y versiones publicadas entre julio y agosto de 2021 (`regex`
2021.8.3 salió nueve días antes del commit). *Deducido*: congela el entorno del autor, no expresa
requisitos mínimos.

**Herramientas:** PyCharm (`.idea/`). No hay herramientas de construcción, linters ni formateadores
configurados.

---

## 3. Estructura del proyecto

```
DGA/
├── lookdga.py          CLI del catálogo: -L -I -G -C -D -B -F (112 líneas, solo stdlib)
├── dga.py              Fachada sobre DGAs/: info, detect, bruteforce, listall, generate, create (285 l.)
├── detectdga.py        ML completo: TLD efectivos, features, datasets, train, test, --check (823 l.)
├── ngram.py            Clase ngrams: contar 1-4-gramas, normalizar, consultar, guardar/cargar (113 l.)
├── statsdga.py         Menú interactivo de estadísticas; se ejecuta al importarse (568 l.)
├── requirements.txt    pip freeze de 2021
├── DGAs/
│   ├── __init__.py     __all__ con los 50 nombres cortos: es el registro de familias
│   ├── <familia>.py    50 módulos; uno por variante (locky2, locky3…)
│   └── wordlist/       words1-3.txt (suppobox), luther/rfc4343/nasa/gpl (gozi), words.json (nymaim2),
│                       effective_tld_names.dat (sufijos públicos), top-1m.csv (Alexa, 638.215 líneas)
├── ml-data/            367 MB versionados: *.dom (listas de dominios), tranco.ng1-4, full/tiny(.pkl,-scaler.pkl)
├── yara/               35 reglas de Malpedia (junio 2021); no las lee ningún código
├── .idea/              Proyecto PyCharm; versionado aunque .gitignore lo excluye
├── LICENSE             GPL v2
└── docs/               Documentación de la puesta a punto (2026)
```

**Para orientarse:**
- Cambiar o añadir una familia: `DGAs/<familia>.py` y su nombre en `DGAs/__init__.py`.
- Cambiar cómo se reconoce o atribuye un dominio: `dga.py:110-193`.
- Cambiar el modelo: `detectdga.py`. Las características se calculan en cuatro sitios casi idénticos
  (`:257-287`, `:307-337`, `:367-397/417-447`, `:477-507`, `:650-680`).

---

## 4. Modelo de datos

No hay motor de almacenamiento ni migraciones. Todo son **ficheros en disco**, con rutas relativas
escritas en el código, y el «esquema» está en ese mismo código.

### 4.1 Entidades

| Entidad | Dónde vive | Estructura real |
|---|---|---|
| **Familia/variante** | `DGAs/<nombre>.py`, clase `DGA` | Atributos de clase: `shortname, name, ref[], desc, yara, samples (int, 0 = sin tope), lcg, use_date (False o nº de días), use_seed (texto), configs[] (semillas; [None] si no hay), variation, regex, ends[]`. Instancia: `DGA(date=datetime, seed=str)`; `get_domain() → str` |
| **Registro de familias** | `DGAs/__init__.py` | Lista `__all__`; el orden es el de `-L` |
| **Dominio etiquetado (corpus)** | stdout de `-C` → `ml-data/mydgas.dom` | CSV sin cabecera `dominio,familia,config,AAAA-MM-DD`, con líneas `* …` ANSI intercaladas |
| **Feed DGA externo** | `ml-data/dga.dom` | TSV de 360 Netlab `familia\tdominio\tinicio\tfin`, comentarios `#` |
| **Lista de dominios legítimos** | `ml-data/tranco-{main,test2,ngram}.dom`, `alexa.dom` | Un dominio por línea (`tranco-ngram` con CRLF) |
| **Diccionario de n-gramas** | `ml-data/tranco.ng1..ng4` | Pickle de `pandas.DataFrame`: índice = n-grama, columna `value` ∈ [0,1] (MinMax por orden n) |
| **Conjunto de características** | `ml-data/{main,secondary,alexa}.pkl` (no versionados) | Pickle de DataFrame con 28 columnas: `sld, tld, family, dga(0/1), len, crctld, vowels, consonants, numbers, doubled, repeated, sylnumber, sylmin, sylmax, mean1..stddev4 (12), entropy, gini` (`detectdga.py:341-346`) |
| **Modelo** | `ml-data/{variante}.pkl` | Pickle de `RandomForestClassifier` (scikit-learn 0.24.2) |
| **Escalador** | `ml-data/{variante}-scaler.pkl` | Pickle de `StandardScaler` (0.24.2) |
| **Sufijos efectivos** | `DGAs/wordlist/effective_tld_names.dat` + 154 literales en `detectdga.py:31-58` | Se cargan en la lista global `etlds` |

### 4.2 Relaciones y contratos implícitos

- **Las variantes del modelo dependen del orden de las columnas.** Una variante es «conjunto principal menos
  ciertas columnas» (`detectdga.py:529-549`, repetido en `:596-616`). `X = df.iloc[:, 1:]` supone que `dga`
  es la primera columna tras quitar `sld/tld/family` (`:552-553`). `testdomains()` vuelve a declarar las 24
  columnas a mano (`:684-689`). **Nada garantiza que coincidan, salvo copiar con cuidado.**
- **Cada modelo forma pareja con su escalador** por convención de nombre (`{dataset}.pkl` +
  `{dataset}-scaler.pkl`).
- **El diccionario de n-gramas debe ser el mismo con el que se entrenó el modelo.** No hay versión ni hash
  que lo garantice.

### 4.3 Cómo se «migra»

No se migra: cualquier cambio de características obliga a regenerar `main.pkl` y a reentrenar. Los pickles
quedan **atados a las versiones exactas de scikit-learn y pandas**. Verificado: `full.pkl` no carga en
scikit-learn 1.9.1 (`docs/MVP.md` §0).

---

## 5. Interfaces y contratos

### 5.1 CLI (la única interfaz pública)

| Orden | Opciones | Contrato de salida |
|---|---|---|
| `lookdga.py` | grupo excluyente `-L -I -G -C -D -B -F`; `-d AAAA-MM-DD`, `-n N` (10), `-m familia…`, `-s semilla`, `-b días` (366) | Texto libre con colores ANSI; `-C` en CSV con líneas de estado |
| `detectdga.py` | `--ngram`, `--main`, `--secondary`, `--alexa`, `--train V`, `--test_secondary V`, `--test_alexa V`, `--check dom…`, `-b` | Texto libre con colores ANSI. **No son excluyentes:** si se pasan varias, gana la primera de la cadena `if/elif` (`:763-819`) |
| `statsdga.py` | ninguna; menú `input()` 0-9 | Texto libre |

**Códigos de salida:** los errores de usuario terminan con `exit()`, es decir, código 0 (`lookdga.py:55,74,84`).
Las excepciones no capturadas dan 1. No hay contrato de códigos.

### 5.2 Fronteras entre módulos

- **Generador ↔ fachada.** Contrato por nombres de atributo, con *duck typing* y sin clase base. La fachada
  da por hecho que todo módulo listado en `__all__` define `DGA` con todos los atributos. Además, como usa
  `eval(nombre)`, el nombre del módulo debe coincidir con el nombre global importado.
- **Fachada ↔ CLI.** Las funciones de `dga.py` tienen un parámetro `main` que decide si **imprimen o
  devuelven** el resultado (`dga.py:55,110,137,196,204,236`). Es la misma función con dos contratos.
  `detect()` fuerza además `brute=True` cuando `main=False` (`:111-112`).
- **`ngram.py` ↔ `detectdga.py`.** `getall(domain, n)` devuelve `(media, mediana, desviación)` del primer
  label, o `(None, None, None)` si mide 3 caracteres o menos. `detectdga.py` filtra antes con `sldtld()` y
  nunca llega a ver los `None`.
- **Duplicaciones entre módulos:** `Col` (colores) está definida igual en `lookdga.py:7` y `dga.py:7`. Las
  cuentas de vocales y consonantes existen dos veces con criterios distintos: `vcn()` (`detectdga.py:131`,
  divide por la longitud) y `vcrel()` (`statsdga.py:16`, divide por vocales + consonantes). Las letras dobles y
  repetidas también están dos veces (`detectdga.py:147-167` y `statsdga.py:106-176`).

### 5.3 Red

- **Saliente:** `nltk.download('brown')` si falta el corpus (`detectdga.py:20-23`, `statsdga.py:10-13`). Se
  ejecuta **al importar el módulo**, sin confirmación.
- **Preparada y no usada:** consultas DNS de hasta 60 tipos de registro (`detectdga.py:69-85`).
- **Entrante:** ninguna.

---

## 6. Aspectos transversales

- **Configuración:** no hay fichero, variables de entorno ni opciones de rutas. Todo está en el código:
  - rutas relativas al directorio de trabajo (`"ml-data/…"`, `"DGAs/wordlist/…"`), así que **hay que lanzarlo
    desde la raíz del repositorio**;
  - hiperparámetros (`n_estimators=30`, `min_samples_leaf=5`, `random_state=1`, `test_size=0.2`,
    `random_state=100`, `detectdga.py:555,567`);
  - `n_jobs=14`, ajustado a la máquina del autor (motivo no documentado);
  - 10 posiciones de fuerza bruta en `--check` (`:718`).
- **Gestión de errores:** predominan los `except:` desnudos que se tragan cualquier error:
  - `lookdga.py:52,70,81`;
  - `dga.py:227` (fallo de un generador ignorado);
  - `detectdga.py:22,83,199,213`;
  - `statsdga.py:567`, que convierte cualquier excepción en «Incorrect option».
  Los fallos de entrada en `--check` no se tratan: la lista vacía produce un `ValueError` (verificado).
- **Logging y observabilidad:** solo `print` con colores ANSI (clase `Col`), barras de progreso hechas con
  `=` cada 100.000 líneas (`detectdga.py:251-252…`) y el `verbose=1` de scikit-learn. No se registra nada en
  fichero.
- **Concurrencia:** solo la interna de scikit-learn (`n_jobs=14` en entrenamiento y predicción; en
  `--check` aparece «Using backend ThreadingBackend with 14 concurrent workers»). La fuerza bruta es
  secuencial. No hay trabajos en segundo plano.
- **Estado global:** `etlds` es una lista global que se rellena una vez (`detectdga.py:25-66`). Las
  comprobaciones `line not in etlds` sobre una lista de miles de elementos hacen la carga cuadrática.
- **Internacionalización:** no hay. La interfaz está en inglés, con restos en español (`statsdga.py:412`:
  «Rango tipico»). Los IDN se tratan solo en su forma `xn--`.
- **Portabilidad:** las rutas usan `/` (Python lo acepta en Windows). Los colores ANSI se ven como basura en
  consolas que no los interpretan (**suposición** para Windows antiguos). Siete generadores usan `ctypes`
  para enteros de 32 bits, lo cual es portable.

---

## 7. Seguridad

Descripción del estado actual; la auditoría es un paso aparte.

- **Autenticación, autorización y secretos:** no aplican. Herramienta local sin usuarios ni credenciales;
  no hay secretos en el repositorio (revisión visual del árbol, no de todos los ficheros de datos).
- **Deserialización de pickles:** se cargan `ml-data/*.pkl` y `tranco.ng*` con `pickle.load` y
  `pd.read_pickle` (`detectdga.py:623,629,695,701`; `ngram.py:52-55`). Cargar un pickle equivale a ejecutar
  código arbitrario: cualquiera que clone el repositorio, o un fork modificado, confía ciegamente en esos
  ficheros. **Es el riesgo principal**, porque el proyecto se distribuye públicamente con los pickles dentro.
- **`eval` con datos derivados de la entrada:**
  - `lookdga.py:68`: `eval(f"dga.{item}")` con el argumento `-m`. Lo controla quien ejecuta la orden;
    el riesgo es bajo.
  - `ngram.py:61-62`: `eval` con el n-grama del dominio analizado. Verificado: solo se alcanza con n-gramas
    que ya están en el diccionario, así que hoy no es explotable. Bastaría un diccionario regenerado con
    datos que contengan comillas para que lo fuera.
  - `dga.py`: `eval(nombre)` sobre nombres de `__all__`, que son fijos.
- **Validación de entradas:** mínima. Las fechas se validan (`lookdga.py:49-55`); los dominios no, y se
  descartan en silencio (`detectdga.py:113-128`).
- **Red:** descarga implícita de NLTK al importar; sin TLS propio, depende de NLTK. Las consultas DNS
  muertas filtrarían a la red los dominios analizados si alguien las reactivara.
- **Material de malware:** el repositorio no contiene binarios. Las reglas YARA son texto. Los generadores
  solo producen nombres de dominio.
- **Cadena de suministro:** dependencias de 2021 sin parches posteriores. Las versiones exactas de pandas,
  scikit-learn y scipy no tienen binarios para arm64 en macOS, y compilarlas desde las fuentes falla
  (verificado).

---

## 8. Estrategia de pruebas

**No hay ninguna:**
- no hay directorio `tests/`;
- no hay `pytest`, `unittest` ni `doctest`;
- no hay vectores de referencia para los generadores;
- no hay CI.

Comandos de prueba: **ninguno**. Las únicas comprobaciones que trae el proyecto son las métricas que
imprimen `--train` y `--test_*`, que no se guardan.

**Lo que se ha comprobado a mano** en la puesta a punto (`docs/MVP.md`):
- entorno Python 3.9.6 x86_64 bajo Rosetta con las versiones de `requirements.txt`;
- `lookdga.py -L/-I/-G/-C/-D/-B/-F`;
- `detectdga.py --check` y `-b --check`;
- `--secondary` (falla);
- opciones 1, 2 y 4-8 de `statsdga.py`.

**Sin cubrir de ningún modo:**
- 39 de 50 generadores, sin confirmación externa;
- `--ngram`, `--main`, `--alexa`, `--train`;
- la opción 3 de estadísticas y la 9 en su rama DGA;
- todas las rutas de error.

---

## 9. Compilación, CI y despliegue

- **Compilación:** no hay. Son scripts interpretados.
- **Distribución:** **clonar el repositorio de GitHub** (`git@github.com:dpgon/DGA.git`), datos y modelos
  incluidos (repositorio de 113 MB comprimidos, 367 MB en `ml-data/`). No hay paquete en PyPI, ni
  `setup.py`/`pyproject.toml`, ni imagen de contenedor, ni releases ni etiquetas.
- **Instalación documentada:** `pip install -r requirements.txt` en un entorno virtual «de Python 3.7 o
  superior» (README). En la práctica funciona con **Python 3.9 en x86_64**:
  ```bash
  # Comprobado en macOS Apple Silicon:
  arch -x86_64 /usr/bin/python3 -m venv venv39x
  arch -x86_64 venv39x/bin/pip install --only-binary :all: -r requirements.txt
  ```
- **Ejecución:** `python <script>.py …` **desde la raíz del repositorio**.
- **CI:** no hay.
- **Actualización:** `git pull`. El modelo cambia solo si alguien sube nuevos `.pkl`. No hay versionado de
  modelos ni de datos.
- **Límite de la plataforma:** `full.pkl` pesa 99.897.641 bytes, a unos 100 KB del máximo por fichero de
  GitHub (100 MB). Cualquier modelo algo mayor no se podría subir sin Git LFS.

---

## 10. Objetivos de rendimiento

El proyecto **no declara ninguno**. Cifras medidas en la puesta a punto, en macOS Apple Silicon bajo
emulación x86_64, que es más lento que nativo:

| Operación | Medida |
|---|---|
| `detectdga.py --check` con 5 dominios | 27 s en total; la predicción del bosque en sí, 0,2 s. El resto es carga de modelo, n-gramas, sufijos y silabeador |
| `detectdga.py -b --check` con 5 dominios | 1 min 51 s |
| `lookdga.py -B` con 2 dominios (366 días × 10 posiciones) | 4 min 11 s |
| `lookdga.py -F` | 1.784 dominios; tiempo no medido |
| `lookdga.py -n 100 -C` (50 familias) | 5.000 dominios; tiempo no medido |
| Entrenamiento y construcción de conjuntos | **No medido**. Recorre unos 3 M de dominios con `eval` por n-grama; **suposición**: horas |

**Tamaños:**
- modelo `full`: 95 MB;
- `tiny`: 55 MB;
- diccionario de 4-gramas: 8,9 MB;
- `dga.dom`: 99 MB.

**Las cifras que importarían en este producto** son el tiempo por dominio en `--check` (para listas
grandes, ver `docs/FUTURE.md` 1.2.5) y el coste de la fuerza bruta por familia candidata.

---

## 11. Registro de decisiones

**D** = documentado (README o commit) · **C** = deducido del código o de los ficheros · **U** = contado por
el usuario

| Decisión | Motivo | Cómo se sabe |
|---|---|---|
| Python 3, en Linux x86_64 con PyCharm | Entorno de trabajo del autor durante el máster | U; C (`.idea/misc.xml`) |
| Reimplementar los DGA a partir de Johannes Bader | Partir de implementaciones fiables y citadas | D (README) |
| Un módulo por variante con clase `DGA` y metadatos de clase | Facilita la fuerza bruta y la ficha genérica. El motivo concreto no está documentado | C |
| Registro por `__all__` + `from DGAs import *` + `eval` | Motivo no documentado; parece la vía más corta para iterar por nombre | C |
| Random Forest (`RandomForestClassifier`, 30 árboles) | Motivo no documentado. El autor lo describe como el núcleo del detector | U (propósito); C (`detectdga.py:567`) |
| N-gramas 1–4 sobre Tranco como característica principal | Medir cuánto se parece un SLD a los dominios humanos | U; C (`ngram.py`) |
| Tranco para entrenar y Alexa para probar | Tranco resiste mejor la manipulación (**suposición**); Alexa como segunda fuente independiente, aunque en realidad no lo es: solapamiento del 62 % | D (README, fuentes); C (solapamiento) |
| Feed de 360 Netlab como DGA de entrenamiento | Fuente pública de dominios DGA reales | D (README) |
| CRC32 del TLD como característica numérica | Motivo no documentado | C (`detectdga.py:260`) |
| Variantes del modelo (`ngram`, `nosyll`, `tiny`…) | Estudio de ablación: ver qué aporta cada grupo de características | C (`detectdga.py:529-549`) |
| Versionar datos y modelos en git | Que `--check` funcione al clonar | D (README: «The repository has the full model») |
| Pickle como formato de persistencia | Lo que ofrecen por defecto pandas y scikit-learn. Motivo no documentado | C |
| `requirements.txt` como `pip freeze` | Congelar el entorno, añadido un día después | C (commit `269b362`) |
| `n_jobs=14` | Ajustado a la máquina de entrenamiento | C; U (el entorno) |
| 10 posiciones y 366 días en la fuerza bruta | Motivo no documentado; acota el coste | C (`lookdga.py:23-25`, `detectdga.py:718`) |
| Extractor de características copiado 4 veces | **Accidental:** crecimiento por copia | C |
| Ignorar `.idea` tras haberlo versionado | **Accidental:** ignorarlo no lo saca del índice | C (commits `fde8bb0`, `269b362`) |
| Reglas YARA incluidas sin uso | Motivo no documentado; material de referencia del estudio | D (README); C |
| `dnspython` y `existdomain()` sin uso | **Accidental:** experimento que quedó | C |

---

## 12. Deuda y riesgos

| # | Riesgo / deuda | Dónde | Impacto |
|---|---|---|---|
| 1 | Dependencias de 2021 sin binarios en plataformas actuales; Python 3.9 sin soporte desde octubre de 2025 | `requirements.txt` | No se instala en sistemas actuales tal como se documenta (verificado en arm64) |
| 2 | Modelos atados a scikit-learn 0.24.2 | `ml-data/*.pkl` | No cargan en scikit-learn actual (verificado). Actualizar obliga a reentrenar |
| 3 | Deserializar pickles de un repositorio público | `detectdga.py:623-701`, `ngram.py:52-55` | Ejecución de código arbitrario si los ficheros se alteran |
| 4 | Sin pruebas ni CI | — | Cualquier cambio puede romper un generador sin que nadie lo note. 39 de 50 no tienen confirmación externa |
| 5 | Desalineación de veredictos y descartes silenciosos | `detectdga.py:650,709-710`, `:113-128` | Resultados atribuidos al dominio equivocado (verificado) |
| 6 | Extractor de características duplicado 5 veces y columnas declaradas a mano | `detectdga.py:257-680` | Cambiar una característica exige tocar 5 sitios y mantener el orden; el riesgo de desfase entre entrenamiento y predicción es silencioso |
| 7 | Contrato de generadores por *duck typing* + `eval` | `dga.py`, `DGAs/__init__.py` | Un atributo mal escrito solo falla en ejecución; un `eval` sobre una entrada nueva sería una vía de inyección |
| 8 | Funciones con doble contrato (`main=True/False`) | `dga.py:55-285` | Mezclan presentación y lógica: no se pueden reutilizar ni probar limpiamente |
| 9 | `except:` desnudos | `dga.py:227`, `detectdga.py:83,199,213`, `statsdga.py:567`… | Los errores reales desaparecen |
| 10 | Patrones sin escapar ni anclar | `dga.py:117-125` | Falsos positivos masivos (`google.com` frente a 6 familias, verificado) y fuerza bruta innecesaria |
| 11 | Rutas relativas al directorio actual | todos los scripts | Falla al ejecutarse desde otra carpeta |
| 12 | Descarga de red al importar | `detectdga.py:20-23`, `statsdga.py:10-13` | Rompe el requisito «sin conexión una vez instalado» (`docs/IDEA.md`) |
| 13 | `statsdga.py` sin `if __name__ == "__main__"` | `statsdga.py:421` | No se puede importar ni probar |
| 14 | 367 MB de datos en git; `full.pkl` a unos 100 KB del límite de GitHub | `ml-data/` | Clonado pesado; un modelo mayor no se podría subir sin LFS |
| 15 | Conjuntos de evaluación no independientes, y Alexa ya no existe | `ml-data/alexa.dom`, `mydgas.dom` | Las métricas no son fiables y la fuente no se puede renovar |
| 16 | `n_jobs=14` fijo | `detectdga.py:567` | Sobresuscripción o rendimiento pobre en otras máquinas; se guarda dentro del modelo |
| 17 | `.idea/` versionado pese al `.gitignore` | `.idea/` | Ruido en el repositorio y configuración personal publicada |
| 18 | Licencias mezcladas sin revisar (GPL v2, CC BY‑SA 4.0 de las reglas, origen de los algoritmos) | `LICENSE`, `yara/*.yar` | Riesgo de incompatibilidad al redistribuir |
