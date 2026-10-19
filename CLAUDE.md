# CLAUDE.md: acuerdo de trabajo para DGA

Instrucciones para agentes de IA y personas que contribuyan a este repositorio. Léelas antes de tocar nada.

## Qué es

DGA es un laboratorio de terminal, nacido en un máster de análisis de malware, para estudiar los algoritmos de
generación de dominios (DGA). Tiene tres partes:

- un catálogo de 50 generadores reimplementados (`lookdga.py`): ficha, generación, lista de bloqueo, sospecha
  por patrón y atribución por fuerza bruta;
- un detector Random Forest que clasifica dominios como generados o humanos (`detectdga.py`);
- un menú de estadísticas (`statsdga.py`).

Su público es quien lo descubre en GitHub para aprender o evaluarlo, no analistas en producción. Está en
puesta a punto: desde la fase 5 de `TODO.md` funciona en Python 3.12 y 3.13 con un modelo reentrenado.

Documentos de referencia, todos en `docs/`:

| Documento | Para qué consultarlo |
|---|---|
| `ESTUDIO.md` | Lo que hace el código, con pruebas |
| `IDEA.md` | Propósito, usuarios, principios y **no objetivos** |
| `MVP.md` | Qué funciona hoy, verificado ejecutándolo |
| `FUTURE.md` | Etapas 1.1 Puesta a punto → 1.2 Vigencia → 1.3 YARA |
| `ARCHITECTURE.md` | Arquitectura real, decisiones y deuda |

Si algo de aquí contradice a esos documentos, manda el documento más reciente y avisa de la contradicción.

## Arquitectura en breve

Scripts sin empaquetar que se comunican por ficheros y por la salida estándar. Versión completa en
`docs/ARCHITECTURE.md`.

```
lookdga.py    CLI del catálogo (solo biblioteca estándar) ─┐
statsdga.py   menú de estadísticas ────────────────────────┼─► dga.py (fachada) ─► DGAs/<familia>.py (50)
detectdga.py  features + RandomForest + --check ───────────┘        └─ from DGAs import * + eval(nombre)
ngram.py      diccionario de n-gramas (lo usan detectdga y statsdga)
nlpdata.py    comprueba que está el corpus brown de NLTK, sin descargarlo
fetchdata.py  descarga y verifica los datos de ml-data/MANIFEST (solo biblioteca estándar)
DGAs/wordlist/  diccionarios de generadores, lista de sufijos públicos (2026); top-1m de Alexa se descarga
ml-data/        MANIFEST en git; listas *.dom, tranco.ng1-4.csv y full/tiny .skops/.json se descargan
yara/           35 reglas de Malpedia, hoy sin uso en el código
docs/           documentación de la puesta a punto (en español)
```

## Entorno, ejecución y pruebas

- **Python 3.12 o 3.13**, nativo (también en Apple Silicon), con las versiones exactas de
  `requirements-lock.txt`:
  ```bash
  python3.13 -m venv venv
  venv/bin/pip install -r requirements-lock.txt -r requirements-dev.txt
  ```
  `venv/` ya está ignorado. Para un nombre distinto, crea el entorno fuera del repositorio. `requirements.txt`
  solo lista las dependencias directas con su versión mínima; el lock se regenera con
  `uv pip compile requirements.txt --universal --python-version 3.12 -o requirements-lock.txt`.
- **El entorno de 2021** (Python 3.9 x86_64, pickles de scikit-learn 0.24.2) solo existe en la etiqueta `v2021`
  y en el juego de datos `2021`. El código actual no carga esos pickles.
- **Ejecuta siempre desde la raíz del repositorio:**
  - `python lookdga.py -L`
  - `python lookdga.py -m tinba -n 5 -G`
  - `python lookdga.py -B nvfowikhevmy.net`
  - `python detectdga.py --check google.com nvfowikhevmy.net`
  - `python statsdga.py`
- **Datos:** no están en git. Tras clonar e instalar, `python fetchdata.py --nltk` descarga los ficheros del
  juego `2026` de `ml-data/MANIFEST` (assets de las releases `model-2026` y `data-2026`, o la fuente original),
  comprueba su SHA‑256 y borra los que no coinciden; nunca sobrescribe un fichero local distinto. `--set 2021`
  instala el juego del máster (release `v2021`) y `--from <dir>` copia desde un directorio local en vez de
  descargar.
- **Sin red:** los scripts nunca descargan nada. El corpus `brown` de NLTK se instala una vez con
  `python -m nltk.downloader -d <dir> brown` (y `NLTK_DATA=<dir>` si no es `~/nltk_data`). Si falta,
  `nlpdata.requirebrown()` detiene el script con ese comando. No vuelvas a poner descargas al importar.
- **Compilación:** no hay.
- **Pruebas** (`tests/`, `pytest`), desde la raíz del repositorio:
  ```bash
  pip install -r requirements-dev.txt
  NLTK_DATA=<ruta con corpora/brown> pytest      # por defecto, sin las lentas (~1 min en Apple Silicon)
  NLTK_DATA=<ruta con corpora/brown> pytest -m slow   # las lentas (> 30 s cada una)
  ```
  - Sin `NLTK_DATA`, las pruebas que necesitan el corpus se saltan; nunca lo descargan.
  - Marcadores: `slow` (más de 30 s) y `model` (necesita `ml-data/full.skops`, su escalador, `full.json` y el
    diccionario).
  - Las de `tests/test_lookdga.py`, `test_generators.py`, `test_check.py` y `test_statsdga.py` son de
    **caracterización**: fijan lo que hoy funciona según `docs/MVP.md`. Si una falla tras un cambio, has roto
    algo que funcionaba; no la ajustes sin entender por qué.
  - `tests/data/snapshot_2026-10-18.csv` fija los 3 primeros dominios de cada familia y semilla. Ningún
    cambio de versiones debe alterarla.
  - Con `-G`, `-C` o `-F`, pasa siempre `-d`: sin fecha se usa la hora actual, y pizd, pykspa2 y suppobox
    cambian de dominios según la hora.
  - **Las pruebas se ejecutan en UTC** (`tests/conftest.py` fija `TZ=UTC`). pykspa2 y suppobox usan
    `time.mktime`, que trabaja en hora local, y dan dominios distintos según la zona horaria de la máquina. Si
    regeneras la instantánea, hazlo con `TZ=UTC`.
- **CI en local** con `act` (no se sube nada a GitHub durante la actualización). Hace falta pasarle el
  `PATH` de la imagen, porque `act` lo pierde cuando `setup-python` añade sus rutas y entonces las acciones
  de Node, como `actions/cache`, no encuentran `node`:
  ```bash
  act push -j tests -P ubuntu-latest=catthehacker/ubuntu:act-22.04 --container-architecture linux/amd64 \
    --matrix os:ubuntu-latest --bind \
    --env PATH=/opt/acttoolcache/node/24.19.0/x64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  ```
  `act` solo ejecuta los trabajos de Linux de la matriz. `--bind` monta el repositorio en vez de copiarlo, para
  que el contenedor vea `ml-data/`: hasta la fase 7 las releases `model-2026` y `data-2026` no están
  publicadas y `fetchdata.py` no puede descargarlas.
- Lo que las pruebas no cubren, compruébalo a mano con los criterios de `docs/MVP.md`. Di qué ejecutaste y qué
  viste; lo que no ejecutaste, llámalo «no verificado».

## Estándares de código que el proyecto ya sigue

Respeta el estilo existente aunque no sea el ideal. Las mejoras de estilo van en cambios aparte.

- **Formato:** 4 espacios, f-strings, líneas de hasta unos 120 caracteres (estilo por defecto de PyCharm).
  No hay linter ni formateador configurados: **no reformatees ficheros enteros**.
- **Nombres:**
  - funciones en minúsculas sin guiones bajos (`createmaindataset`, `sldtld`, `testdomains`);
  - variables cortas (`ng`, `sc`, `LP`, `nr`);
  - cada generador es una clase `DGA` en `DGAs/<nombrecorto>.py`.
- **Comentarios y textos:** en inglés en el código, la CLI y el README. Los docstrings son escasos y usan
  `'''…'''` con `:param:`/`:return:` (`detectdga.py:114-118`). La documentación de `docs/` va en español.
- **Salida:** `print` con la clase `Col` de colores ANSI. No hay logging. No añadas `print` en las rutas cuya
  salida se redirige a ficheros (`dga.create` con `main=True`).
- **Errores:** el código existente usa `except:` desnudos y `exit()`. **No copies ese patrón en código
  nuevo:** captura excepciones concretas e informa del error (ver `docs/ARCHITECTURE.md` §12, punto 9).
- **Funciones de `dga.py`:** siguen el patrón `main=True` imprime / `main=False` devuelve. Si añades una,
  respétalo, o sepáralo de forma explícita.

## Git

- Historial: dos commits en `main` (agosto de 2021), sin ramas, etiquetas ni pull requests.
- Mensajes cortos en inglés, en tercera persona del presente y con mayúscula inicial
  (`Updates readme, requirements and gitignore (.idea)`). Sigue ese formato.
- No hagas commit ni push sin que lo pida el usuario. Si se trabaja en algo grande, usa una rama.
- **Mientras dure la actualización de `TODO.md`, no se sube nada a GitHub**: ni push, ni etiquetas, ni
  releases. Todo se publica de una vez en su fase 7 (decisión del autor, 2026-10-18).
- No subas ficheros de más de 100 MB: GitHub los rechaza, y el `full.pkl` de 2021 ya pesaba 99,9 MB.

## Reglas propias, fáciles de incumplir

1. **Lanza todo desde la raíz del repositorio.**
   *Por qué:* todas las rutas son relativas al directorio actual (`"ml-data/…"`, `"DGAs/wordlist/…"`). Desde
   otra carpeta falla con `FileNotFoundError`, o peor, escribe pickles donde no toca.
2. **Una familia nueva necesita tres cosas que coincidan:**
   - el fichero `DGAs/<x>.py`;
   - `shortname = "<x>"`;
   - `"<x>"` en `DGAs/__init__.py::__all__`.
   Además, debe definir **todos** los atributos de clase: `shortname`, `yara`, `name`, `ref`, `desc`,
   `samples`, `lcg`, `use_date`, `use_seed`, `configs`, `variation`, `regex` y `ends`.
   *Por qué:* `dga.py` resuelve las familias con `eval(nombre)` y lee los atributos por *duck typing*. Si falta
   uno, no hay error hasta ejecutar `-I` o `-B` con esa familia.
3. **Solo se añaden algoritmos ya publicados por terceros**, con su referencia en `ref` y al menos un caso de
   referencia (fecha, semilla y dominios esperados).
   *Por qué:* es un no objetivo de `docs/IDEA.md` (nada de reversing nuevo), y 39 de los 50 generadores
   actuales no tienen confirmación externa; no hay que agrandar ese hueco.
4. **Las características del modelo se calculan solo en `domainfeatures()`** (`detectdga.py`), en el orden de
   `COLUMNS`. No vuelvas a copiarlas en otra función. Si cambias una, reentrena y pasa la prueba de paridad
   (`tests/test_model.py`, `slow`).
   *Por qué:* el modelo solo ve un vector por posición. Si el orden de entrenamiento y el de predicción no
   coinciden, el detector da veredictos erróneos sin ningún aviso. Hasta 2026 estaban copiadas en cinco sitios.
5. **Modelo, escalador, diccionario de n-gramas y lista de sufijos van juntos.** Si cambias uno, regenera los
   otros y vuelve a medir.
   *Por qué:* `ml-data/{modelo}.json` guarda sus SHA‑256 y `loadmodel()` se niega a cargar si no coinciden. No
   lo esquives editando los hashes del JSON: las predicciones serían erróneas en silencio.
6. **No actualices scikit-learn, pandas ni numpy sin reentrenar o comprobar que el modelo carga y da los mismos
   veredictos.**
   *Por qué:* los pickles de scikit-learn 0.24.2 no cargan en scikit-learn 1.9.1 (verificado, `docs/MVP.md`
   §0). skops tampoco garantiza que un modelo cargue en otra versión de scikit-learn.
7. **Los modelos se guardan con skops, nunca con pickle, y `TRUSTED` (`detectdga.py`) no se amplía para que
   cargue un fichero.** Tampoco cargues pickles de origen desconocido.
   *Por qué:* `pickle.load` ejecuta código, y el repositorio es público y obliga a cargar sus modelos
   (`docs/ARCHITECTURE.md` §7). skops solo acepta los tipos de la lista; `sklearn.tree._tree.Tree` está en
   ella porque los modelos los genera el proyecto y el manifiesto fija su SHA‑256. Los `.pkl` que quedan
   (`main`, `secondary`, `umbrella`) son conjuntos intermedios que genera cada uno en local; no se publican.
8. **Los conjuntos de evaluación no pueden compartir dominios con el de entrenamiento.** Compruébalo al
   construirlos y publica las métricas solo si se cumple.
   *Por qué:* `alexa.dom` comparte el 62 % con `tranco-main.dom`, y por eso las métricas actuales no valen.
   La honestidad de los resultados es un principio de `docs/IDEA.md`.
9. **El programa nunca contacta con los dominios analizados.** No reactives `existdomain()`/`checkdomains()`
   (`detectdga.py:69-106`) sin que el usuario resuelva el punto 1.1.10 de `docs/FUTURE.md`.
   *Por qué:* es un no objetivo, y consultar el DNS de un dominio DGA filtra hacia fuera qué se está
   investigando.
10. **Nunca ejecutes muestras de malware.** Cualquier análisis de ficheros (etapa 1.3, YARA) es estático.
    *Por qué:* es un no objetivo y un requisito de seguridad del producto.
11. **No añadas dependencias de red en tiempo de ejecución.** Después de instalar, todo debe funcionar sin
    conexión.
    *Por qué:* es un requisito de `docs/IDEA.md` (máquinas de análisis aisladas). La descarga de NLTK al
    importar es deuda conocida, no un modelo a seguir.
12. **Mantén `lookdga.py`, `dga.py` y `DGAs/` libres de dependencias externas.**
    *Por qué:* solo usan la biblioteca estándar y funcionan con cualquier Python 3 sin instalar nada.
13. **No lances `--ngram`, `--main`, `--secondary`, `--umbrella` ni `--train` sin avisar.** Sobrescriben
    ficheros de `ml-data/` y tardan: en la fase 5 (Apple Silicon nativo), `--main` tardó 6 min y `--secondary`
    4 min. Antes, comprueba con `python fetchdata.py` que los ficheros de entrada son los del juego que quieres
    (si no coinciden con el manifiesto, lo dice).
    *Por qué:* `full.skops` y `tranco.ng*.csv` son el modelo publicado. Hay copia en la release `model-2026`,
    pero un modelo regenerado ya no coincide con el manifiesto y `fetchdata.py` deja de dar por bueno ese
    fichero.
14. **`lookdga.py -C` escribe datos en la salida estándar.** No añadas nada más a esa salida.
    *Por qué:* el README la redirige a `ml-data/mydgas.dom`. Las líneas de estado van a la salida de error
    desde C13; no las devuelvas a la estándar.
15. **No edites `ml-data/*.dom` ni `DGAs/wordlist/*` a mano.** Los datos se cambian a través de
    `ml-data/MANIFEST`: fichero nuevo con su URL, tamaño, SHA‑256, fuente (de dónde sale y cómo se obtuvo),
    licencia y juego. No cambies el hash de un fichero que ya está publicado: añade otro.
    *Por qué:* son datos de terceros (Tranco, 360 Netlab, Alexa, Mozilla) y el estudio depende de poder
    reconstruirlos.
16. **No toques `.idea/`.**
    *Por qué:* es configuración personal de PyCharm que quedó versionada por accidente
    (`docs/ARCHITECTURE.md` §11). Qué hacer con ella lo decide el usuario.
17. **Toda afirmación sobre el comportamiento, en docs, README o mensajes, debe estar verificada o marcada
    como «no verificado».**
    *Por qué:* el README original prometía cosas que el código no cumplía (`docs/ESTUDIO.md` §9), y corregir
    eso es el objetivo de la puesta a punto.
