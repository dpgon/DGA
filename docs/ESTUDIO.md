# Estudio del proyecto DGA

> **Nota (2026-10-19):** este estudio es la foto del código de 2021 y no se actualiza. Desde entonces se
> han corregido las versiones, los datos, el formato del modelo y varios errores: lo que cambió y por qué está
> en `docs/CORRECCIONES.md`, y lo que hace hoy el proyecto, en `docs/MVP.md` y `docs/ARCHITECTURE.md`. Las
> referencias de línea de este documento son las del commit `269b362`.

> Estudio hecho el 2026-10-18 leyendo el código del repositorio `dpgon/DGA` (rama `main`, commit `269b362`).
> No se ha ejecutado ningún script del proyecto. Lo que aquí se afirma sale de leer el código y de
> inspeccionar los ficheros de datos con herramientas de solo lectura (`wc`, `head`, `sort`, `comm`, `strings`
> y un análisis estático con `ast` que no importa los módulos). Lo que no sale de un archivo concreto va
> marcado como **suposición**.

---

## 1. En una página

**Qué es.** Un proyecto de máster sobre algoritmos de generación de dominios (DGA) usados por malware. Tiene dos
mitades:

1. Una **colección de 50 generadores DGA** reimplementados en Python 3 (`DGAs/*.py`), casi todos adaptados del
   repositorio de Johannes Bader, con una herramienta de línea de órdenes (`lookdga.py`) que genera dominios
   de cualquier familia para cualquier fecha, los compara con expresiones regulares por familia y hace
   **fuerza bruta** para averiguar qué familia, qué día y en qué posición se generó un dominio concreto.
2. Un **clasificador de aprendizaje automático** (`detectdga.py`) que decide si un dominio parece DGA o humano.
   Es un `RandomForestClassifier` de scikit-learn sobre 24 características del SLD: frecuencias de n-gramas
   (1 a 4) aprendidas sobre la lista Tranco, proporciones de vocales, consonantes y dígitos, sílabas
   (NLTK), entropía, coeficiente de Gini, longitud y CRC32 del TLD. El modelo entrenado viene en el repositorio
   (`ml-data/full.pkl`, 95 MB).

Hay además un menú interactivo de estadísticas (`statsdga.py`) que se usó para estudiar las familias y
ajustar las características, y 35 reglas YARA de Malpedia (`yara/`) que el código solo nombra, nunca usa.

**En qué estado está.** Es un proyecto **terminado como trabajo académico y congelado desde agosto de 2021**:
dos commits en dos días (`fde8bb0` 2021-08-11, `269b362` 2021-08-12) y nada más. No hay pruebas, ni
empaquetado, ni CI. El flujo de detección (`detectdga.py --check`) y el generador (`lookdga.py`) están
completos; el resto del flujo de ML tiene un fallo que impide crear el conjunto secundario tal como lo
describe el README, y la evaluación «Alexa» está contaminada con datos de entrenamiento.

**Lo que más importa saber a día de hoy:**

- Las dependencias están fijadas a versiones de 2021 (`scikit-learn==0.24.2`, `numpy==1.21.1`) y los modelos
  `.pkl` se serializaron con scikit-learn 0.24.2 (`strings ml-data/full.pkl` → `_sklearn_version 0.24.2`).
  **Suposición:** esas versiones solo se instalan en Python ≤ 3.9 y el pickle no carga en scikit-learn ≥ 1.3.
  Si es así, hoy el modelo incluido solo funciona en un entorno con un Python sin soporte.
- `detectdga.py --check` puede **asignar la predicción al dominio equivocado** cuando alguno de los dominios
  pasados se descarta (ver §8.2).
- El 62 % del conjunto de prueba Alexa (310.412 de 500.000 dominios) **está también en el conjunto de
  entrenamiento**, así que las métricas que dé `--test_alexa` sobrestiman el rendimiento (§8.3).
- Dos de las fuentes de datos citadas ya no existen tal cual: el ranking Alexa se retiró en 2022, y del feed
  de 360 Netlab no se ha comprobado si sigue en pie (**suposición**, §10).

---

## 2. Qué hace, funcionalmente

| Capacidad | Qué consigue quien la usa | Dónde |
|---|---|---|
| Listar familias | Ver los 50 generadores disponibles y su nombre largo | `lookdga.py -L` → `dga.listall()` (`dga.py:196`) |
| Ficha de una familia | Referencias, descripción, regla YARA asociada, si usa fecha y cada cuántos días, semillas conocidas, máximo de dominios por fecha, TLD posibles y la expresión regular | `lookdga.py -m <familia> -I` → `dga.info()` (`dga.py:55`) |
| Generar dominios | Obtener los N primeros dominios que una familia generaría en una fecha y con una semilla | `lookdga.py -m <f> -d AAAA-MM-DD -n N -G` → `dga.generate()` (`dga.py:204`) |
| Crear un corpus etiquetado | Volcar N dominios por familia en CSV `dominio,familia,config,fecha`, repartidos entre semillas y retrocediendo en fechas cuando la familia tiene tope diario | `lookdga.py -n N -C` → `dga.create()` (`dga.py:236`) |
| Lista para cortafuegos | Dominios de todas las familias para hoy y los siete días siguientes, sin repetidos | `lookdga.py -F` (`lookdga.py:100-106`) |
| Detección por regex | Saber qué familias podrían haber generado un dominio | `lookdga.py -D dom…` → `dga.detect()` (`dga.py:110`) |
| Fuerza bruta | Confirmar familia, semilla, día y posición en que se generó un dominio, buscando hacia atrás desde la fecha dada | `lookdga.py -B dom… [-d] [-b días] [-n posiciones]` → `dga.bruteforce()` (`dga.py:137`) |
| Clasificar dominios con IA | Saber si un dominio parece DGA; si lo parece, qué familias encajan por regex y, con `-b`, confirmarlo por fuerza bruta | `detectdga.py [-b] --check dom…` → `testdomains()` (`detectdga.py:642`) |
| Reproducir el entrenamiento | Recrear diccionario de n-gramas, conjuntos de datos y modelos, y evaluarlos | `detectdga.py --ngram/--main/--secondary/--alexa/--train/--test_*` (`detectdga.py:737-819`) |
| Estudio estadístico | Topes de dominios por familia, colisiones, alfabeto y regex sugerida, letras dobles y repetidas, proporción vocal/consonante y de dígitos, sílabas, n-gramas; comparando con el top‑1M de Alexa | `statsdga.py` (menú, `statsdga.py:421-568`) |

---

## 3. Cómo está hecho

- **Lenguaje:** Python 3. No hay versión declarada en ningún manifiesto; el README dice «3.7 o superior» y el
  proyecto de PyCharm usa «Python 3.9 (DGA)» (`.idea/misc.xml`).
- **Forma:** cuatro scripts sueltos en la raíz más un paquete `DGAs/`. No hay `setup.py`, `pyproject.toml`
  ni punto de entrada instalable. Todas las rutas son **relativas al directorio actual**
  (`"DGAs/wordlist/..."`, `"ml-data/..."`), así que todo debe lanzarse desde la raíz del repositorio.
- **Interfaz:** solo línea de órdenes (`argparse`) y un menú `input()`. Sin servidor, sin API, sin interfaz
  gráfica: **no hay frontend**.

### Dependencias (`requirements.txt`)

| Paquete (versión fijada) | Para qué se usa | Dónde |
|---|---|---|
| `scikit-learn==0.24.2` | `RandomForestClassifier`, `StandardScaler`, `train_test_split`, métricas; `MinMaxScaler` para normalizar los n-gramas | `detectdga.py:14-17,558,567`; `ngram.py:3,39` |
| `pandas==1.3.1` | DataFrames de características guardados como pickle; tablas de n-gramas | `detectdga.py:341-347`; `ngram.py:37-55` |
| `numpy==1.21.1` | Entropía, Gini, medias/medianas de n-gramas | `detectdga.py:229-237,275-278`; `ngram.py:65` |
| `nltk==3.6.2` | `LegalitySyllableTokenizer` entrenado con el corpus Brown para contar sílabas; **descarga el corpus de Internet al importar** si falta | `detectdga.py:8-23`; `statsdga.py:5-13` |
| `dnspython==2.1.0` | Resolver si un dominio existe (`existdomain`) — **solo lo usa código muerto** | `detectdga.py:10,69-106` |
| `joblib`, `scipy`, `threadpoolctl` | Dependencias transitivas de scikit-learn | — |
| `click`, `regex`, `tqdm` | Dependencias transitivas de NLTK | — |
| `python-dateutil`, `pytz`, `six` | Dependencias transitivas de pandas | — |

`pickle` (biblioteca estándar) guarda modelos y escaladores (`detectdga.py:564,571,623,629,695,701`).

---

## 4. Estructura

| Directorio / módulo | Responsabilidad | Archivos clave |
|---|---|---|
| `lookdga.py` | CLI del generador: parsea argumentos y delega en `dga.py` | `lookdga.py:18-108` |
| `dga.py` | Fachada sobre las familias: info, regex, generación, corpus, fuerza bruta. Accede a cada familia con `eval(nombre)` | `dga.py:18-285` |
| `DGAs/` | Un módulo por variante de DGA (50). Cada uno define `class DGA` con metadatos de clase (`shortname`, `name`, `ref`, `desc`, `yara`, `samples`, `lcg`, `use_date`, `use_seed`, `configs`, `variation`, `regex`, `ends`) y `get_domain()`, que devuelve el siguiente dominio | `DGAs/__init__.py` (lista `__all__`), p. ej. `DGAs/tinba.py`, `DGAs/banjori.py` |
| `DGAs/wordlist/` | Datos que necesitan algunas familias y el ML: diccionarios de suppobox (`words1-3.txt`), gozi (`luther`, `rfc4343`, `nasa`, `gpl`), nymaim2 (`words.json`); lista de sufijos públicos (`effective_tld_names.dat`); top‑1M de Alexa (`top-1m.csv`, 638.215 líneas) | leídos en `DGAs/suppobox.py:20`, `detectdga.py:60,92`, `statsdga.py:110…` |
| `ngram.py` | Clase `ngrams`: cuenta n-gramas 1‑4 del primer label, los normaliza 0‑1 y calcula media/mediana/desviación de un dominio | `ngram.py:6-113` |
| `detectdga.py` | Todo el ML: extracción de características, creación de conjuntos, entrenamiento, evaluación y clasificación | `detectdga.py:109-183` (características), `240-517` (conjuntos), `520-639` (entrenar/evaluar), `642-726` (`--check`) |
| `statsdga.py` | Menú interactivo de estadísticas. Se ejecuta al importarlo (no tiene `if __name__ == "__main__"`) | `statsdga.py:421-568` |
| `ml-data/` | Conjuntos de dominios (`*.dom`), diccionario de n-gramas (`tranco.ng1-4`), modelos y escaladores (`full*.pkl`, `tiny*.pkl`). 367 MB versionados en git | ver §6 |
| `yara/` | 35 reglas YARA autogeneradas de Malpedia (licencia CC BY‑SA 4.0, ver cabecera de `yara/tinba.yar`). Ningún código las lee | `dga.py:62-65` solo imprime el nombre |
| `.idea/` | Configuración de PyCharm, versionada en el primer commit y luego ignorada (`.gitignore`, última línea) | — |
| `.m-terminal/` | Metadatos de la herramienta que lanzó este estudio; no forma parte del proyecto y no está en git | `.m-terminal/run.json` |

Las 50 variantes: banjori, bazarbackdoor1‑4, chinad, corebot, dircrypt, dnschanger, flubot, fobber1‑2, fosniw,
gozi, kraken1‑2, locky2‑3, monero, murofet1‑3, mydoom, necurs, newgoz, nymaim1‑2, padcrypt, pizd, proslikefan,
pushdo, pykspa1‑2, qadars, qakbot, qsnatcha/b, ramdo, ramnit, ranbyus1‑2, shiotob, simda, sisron, suppobox,
symmi, tempedreve, tinba, vawtrak3, zloader (`DGAs/__init__.py`). En todas coincide `shortname` con el nombre de
fichero, y todas las que declaran regla YARA la tienen en `yara/`; cuatro no declaran ninguna (fosniw, pizd,
proslikefan, sisron) — comprobado con un análisis estático de los 50 módulos.

---

## 5. Flujo principal

### 5.1 Generación y fuerza bruta (`lookdga.py`)

1. `lookdga.py:111` → `main()`. `argparse` con un grupo de órdenes excluyentes (`-L -I -G -C -D -B -F`).
2. Fecha por defecto: hoy (`lookdga.py:57`). Familias: las de `-m`, validadas con
   `eval(f"dga.{item}")` (`lookdga.py:68`), o todas (`dga.listall()`).
3. `dga.py:2-4` importa el paquete `DGAs` con `from DGAs import *`, de modo que cada familia queda como un
   nombre global y `dga.py` la alcanza con `eval(nombre).DGA`.
4. **Generar** (`dga.generate`, `dga.py:204`): instancia `DGA(date=…, seed=…)` y llama a `get_domain()` hasta
   `min(n, samples)` veces.
5. **Detectar** (`dga.detect`, `dga.py:110`): por familia, concatena `regex` + alternativa de `ends` y aplica
   `re.match` al dominio.
6. **Fuerza bruta** (`dga.bruteforce`, `dga.py:137`): para cada familia que pasa la regex y cada semilla de
   `configs`, genera las primeras `n` posiciones (10 por defecto) del día, retrocede `use_date` días y repite
   hasta cubrir `-b` días (366 por defecto). Se detiene en la primera coincidencia.

### 5.2 Clasificación con el modelo incluido (`detectdga.py --check`)

1. Al importar, `detectdga.py:20-23` comprueba el corpus Brown y lo descarga si falta (red).
2. `main()` (`detectdga.py:737`) → `testdomains(args.check, brute=args.bruteforce)` (`detectdga.py:642`).
3. `loadetlds()` (`:28`) monta la lista de «TLD efectivos»: 154 sufijos escritos a mano «extraídos de Alexa»
   más `DGAs/wordlist/effective_tld_names.dat`.
4. `loadngram("ml-data/tranco")` (`:203`) carga `tranco.ng1-4`; `LegalitySyllableTokenizer(brown.words())`
   construye el silabeador.
5. Por dominio, `sldtld()` (`:113`) separa primer label y resto; quita un prefijo `www1`, `www2` o `mail`; y
   **descarta** el dominio si el resto no está en la lista de sufijos o el SLD tiene ≤ 3 caracteres.
6. Para cada dominio aceptado calcula 24 características (`:653-680`): `len/63`, `crc32(tld)`, vocales,
   consonantes, dígitos, dobles, repetidas, nº/mín/máx de sílabas, media/mediana/desviación de n-gramas 1‑4,
   entropía y Gini.
7. Escala con `ml-data/full-scaler.pkl` y predice con `ml-data/full.pkl` (`:695-704`).
8. Imprime por dominio «DGA generated» o «No DGA domain»; si es DGA, lanza `dga.detect` y, con `-b`,
   `dga.bruteforce(familias, [dominio], None, None, 10)` — es decir, **solo las 10 primeras posiciones de cada
   día y 366 días hacia atrás desde hoy** (`:713-722`).

### 5.3 Reproducir el entrenamiento (según el código)

```
--ngram     tranco-ngram.dom              → tranco.ng1..ng4        (createstdngram, :217)
--main      tranco-main.dom + dga.dom      → main.pkl               (createmaindataset, :240)
--secondary tranco-test2.dom + mydgas.dom  → secondary.pkl          (createtestdataset, :350)  ⚠ ver §8.1
--alexa     alexa.dom                      → alexa.pkl              (createalexadataset, :460)
--train X   main.pkl                       → X.pkl + X-scaler.pkl   (traindata, :520)
--test_secondary X / --test_alexa X        → matriz de confusión e informe (testsecdata, :584)
```

`X` ∈ {full, ngram, nongram, nosyll, nongramnosyll, tiny}: cada uno elimina un grupo de columnas
(`detectdga.py:529-549`). El entrenamiento usa una partición 80/20 con `random_state=100` y un bosque de
30 árboles, `min_samples_leaf=5`, `n_jobs=14` (`:555,567`).

---

## 6. Datos e interfaces

**Almacenamiento:** todo son ficheros locales; no hay base de datos.

| Fichero | Formato | Contenido real (contado) |
|---|---|---|
| `ml-data/tranco-main.dom` | un dominio por línea | 1.500.000 dominios Tranco (benignos de entrenamiento) |
| `ml-data/tranco-test2.dom` | un dominio por línea | 500.000 dominios Tranco; 0 en común con `tranco-main` |
| `ml-data/tranco-ngram.dom` | un dominio por línea, finales CRLF | 3.241.487 dominios Tranco para el diccionario de n-gramas; 0 en común con los otros dos |
| `ml-data/dga.dom` | feed de 360 Netlab: `familia<TAB>dominio<TAB>inicio<TAB>fin`, cabecera con `#` | 1.451.931 líneas de datos, 57 familias. Banjori (483.160) y emotet (475.580) son el 66 % |
| `ml-data/mydgas.dom` | CSV `dominio,familia,config,fecha` con líneas de estado ANSI | 504.000 dominios generados (444.228 únicos), fechas 2011‑10‑15 a 2019‑12‑31; 31.763 también están en `dga.dom` |
| `ml-data/alexa.dom` | un dominio por línea | 500.000 dominios; 310.412 también están en `tranco-main.dom` |
| `ml-data/tranco.ng1-4` | pickle de `pandas.DataFrame` (índice = n-grama, columna `value` 0‑1) | diccionario de n-gramas |
| `ml-data/full.pkl`, `tiny.pkl` | pickle de `RandomForestClassifier`, scikit-learn 0.24.2 | modelos «full» (24 características) y «tiny» (7) |
| `ml-data/*-scaler.pkl` | pickle de `StandardScaler`, scikit-learn 0.24.2 | escaladores |
| `ml-data/main.pkl`, `secondary.pkl`, `alexa.pkl` | pickle de DataFrame de 28 columnas (`detectdga.py:341-346`) | **no están en el repositorio**; hay que generarlos |
| `DGAs/wordlist/top-1m.csv` | CSV `rango,dominio` | 638.215 líneas (no un millón) |

Esquema de los conjuntos (`detectdga.py:341-346`): `sld, tld, family, dga (0/1), len, crctld, vowels,
consonants, numbers, doubled, repeated, sylnumber, sylmin, sylmax, mean1, median1, stddev1, … mean4,
median4, stddev4, entropy, gini`.

**Red:** la única conexión activa en el flujo vivo es `nltk.download('brown')` al importar `detectdga.py` o
`statsdga.py`. Las consultas DNS (`existdomain`, `detectdga.py:69`) están en código que nadie llama. Los
datos externos (Tranco, 360 Netlab) se descargan a mano según el README.

**Interfaces expuestas:** solo las dos CLI y el menú. No hay API de biblioteca documentada, aunque `dga.py`
se usa como tal desde `detectdga.py` y `statsdga.py`.

**Formatos que escribe:** texto por salida estándar (con códigos de color ANSI, también en `-C`, lo que
ensucia el CSV: ver la primera y la última línea de `ml-data/mydgas.dom`) y pickles en `ml-data/`.

---

## 7. Construcción, ejecución y pruebas

No hay compilación. **Ninguno de estos comandos se ha ejecutado en este estudio**; todos están leídos en el
README o deducidos del código.

```bash
pip install -r requirements.txt                       # README; suposición: requiere Python ≤ 3.9

python lookdga.py -L                                  # README
python lookdga.py -m zloader -I                       # README
python lookdga.py -m tinba -n 5 -G                    # README
python lookdga.py -D google.com nvfowikhevmy.net      # README
python lookdga.py -B google.com nvfowikhevmy.net      # README
python lookdga.py -F                                  # solo en el código (lookdga.py:44)
python lookdga.py -d 2019-12-31 -n 3000 -C > ml-data/mydgas.dom   # README

python statsdga.py                                    # README, menú interactivo

python detectdga.py --ngram | --main | --secondary | --alexa      # README
python detectdga.py --train ngram                     # README
python detectdga.py --test_secondary ngram            # README
python detectdga.py -b --check ughdnmmgdpscliraqnpl.com nvfowikhevmy.net uquslaigwaannie.ddns.net google.com facebook.com   # README
```

Todo debe lanzarse desde la raíz del repositorio por las rutas relativas.

**Pruebas:** no hay ninguna. Ni `tests/`, ni `pytest`, ni `unittest`, ni CI. La única «validación» son las
matrices de confusión que imprimen `--train` y `--test_*`, y no hay resultados guardados de ninguna ejecución
en el repositorio, así que tampoco se sabe qué precisión obtuvo el modelo.

---

## 8. Estado

### Terminado

- **Los 50 generadores** tienen la misma interfaz y metadatos completos (análisis estático de `DGAs/*.py`).
  No se ha comprobado que produzcan los dominios correctos (no hay vectores de prueba en el repositorio).
- **`lookdga.py`** completo en sus siete órdenes (`lookdga.py:88-108`).
- **`detectdga.py --check`** con el modelo incluido: el camino está completo y los ficheros que necesita
  están en `ml-data/` (`full.pkl`, `full-scaler.pkl`, `tranco.ng1-4`).
- **`--ngram`, `--main`, `--alexa`, `--train`, `--test_*`**: completos en código; necesitan regenerar
  `main.pkl`/`alexa.pkl`/`secondary.pkl`, que no se versionaron.

### Roto o a medias

1. **`--secondary` no puede funcionar tal cual.** `main()` exige `ml-data/tranco-secondary.dom`
   (`detectdga.py:775`), pero `createtestdataset()` lee `ml-data/tranco-test2.dom` (`:356`), que es el
   nombre que usa el README y el que está en el repositorio. Siempre imprime «not found».
2. **`--check` puede desalinear predicciones y dominios.** `testdomains()` solo añade a `domains` los que
   pasan `sldtld()` (`:650-651`), pero luego imprime `domlist[c]` con el índice de la predicción (`:709-710`).
   Si se descarta alguno —SLD de 3 letras como `bbc.com`, un `www.` delante (no está en la lista de prefijos
   de `:119`), un subdominio, o un TLD fuera de la lista— el veredicto de un dominio se atribuye a otro. Si se
   descartan todos, `sc.transform` recibe una matriz vacía (`:698`) y falla (**suposición** sobre el error
   exacto).
3. **`statsdga.py` opción 9 con Alexa:** `calcngram(None, ng)` pasa líneas `rango,dominio` sin separar
   (`statsdga.py:260-272`), así que el SLD que mide es `1,google`.
4. **`statsdga.py` opción 2:** `collision()` recorre `range(1000)` sin comprobar la longitud (`:89-90`); con
   familias de tope bajo da `IndexError`, que el `except` general convierte en «Incorrect option» (`:567`).
5. **`dga.create()` solo funciona con `configs=2`** (el valor por defecto): `first` solo se define en esa rama
   (`dga.py:251,253`); con 0 o 1 daría `NameError`.
6. **`checktranco()` comprueba cuatro veces `tranco.ng1`** en vez de ng1‑ng4 (`detectdga.py:730-731`).

### Muerto

- `existdomain()` y `checkdomains()` (`detectdga.py:69-106`): nadie las llama; con ellas sobra `dnspython`.
- `detect()` (`detectdga.py:109`), `RandomForestRegressor` importado (`:16`).
- `statvowels()` y `printserie()` (`statsdga.py:284,386`): nadie las llama.
- `getmean`, `getmedian`, `getstdn`, `getallngrams` (`ngram.py:67-113`): sin uso.
- `show()`, `samples()`, `use_date()` de `dga.py:22-52`: `show` sin uso; las otras solo desde `statvowels`/
  `statletters`.
- `ml-data/tiny.pkl` y `tiny-scaler.pkl` (55 MB): solo los usan `--test_*`, nunca `--check`.
- Las reglas `yara/*.yar`: ningún código las lee.
- Código comentado: una línea (`detectdga.py:563`). Marcas `TODO/FIXME/XXX/HACK`: ninguna.

### Riesgos de mantenimiento que no son fallos

- `eval()` con datos de entrada: el nombre de familia de `-m` (`lookdga.py:68`) y cada n-grama del dominio
  analizado (`ngram.py:61-62`, `eval(f"self.ngram{l}['value']['{ng}']")`). Un dominio con comilla rompe el
  análisis y, en principio, permite inyectar código en una herramienta que procesa dominios de origen dudoso.
- Carga de pickles (`detectdga.py:623,629,695,701`; `ngram.py:52-55`): quien clone el repositorio ejecuta lo
  que contengan. Aceptable para el autor, no para quien descarga un repo público sin auditar.
- Bloques de extracción de características copiados cuatro veces (`detectdga.py:240-517,642-680`).
- 367 MB de datos en git; `full.pkl` pesa 99.897.641 bytes, a 100 KB del límite duro de 100 MB de GitHub.

---

## 9. Lo que el proyecto dice y no cumple

| El README dice | El código hace | Prueba |
|---|---|---|
| El conjunto secundario se crea con `--secondary` a partir de `tranco-test2.dom` | Exige `tranco-secondary.dom`, que no existe | `detectdga.py:775` vs `:356` |
| «Python 3.7 o superior» | Las versiones fijadas son de 2021 y los modelos se serializaron con scikit-learn 0.24.2. **Suposición:** no se instalan en Python ≥ 3.10 ni cargan en scikit-learn moderno | `requirements.txt`; `strings ml-data/full.pkl` |
| La fuerza bruta «detecta el día y el orden de generación» | Solo busca en las primeras `-n` posiciones (10 por defecto) y 366 días hacia atrás desde la fecha dada; desde `--check -b`, siempre 10 posiciones y desde hoy. Un dominio en la posición 11 o de hace dos años sale «no encontrado» | `lookdga.py:22-25`; `dga.py:162-166`; `detectdga.py:718` |
| La detección por regex dice qué familia generó un dominio | Los `ends` se concatenan sin escapar el punto y la regex no se ancla al final (`re.match` sin `$`), así que la coincidencia es más laxa de lo que parece; p. ej. suppobox es `[a-z]{12,28}` + `.net` | `dga.py:117-125`; `DGAs/suppobox.py:16-17` |
| `statsdga.py` compara con la lista Alexa top million | El fichero tiene 638.215 líneas, no un millón; la opción 9 mide mal los dominios Alexa | `DGAs/wordlist/top-1m.csv`; `statsdga.py:260-272` |
| `--test_alexa` sirve para validar el modelo | 310.412 de los 500.000 dominios de `alexa.dom` están en `tranco-main.dom`, el conjunto de entrenamiento; la prueba no es independiente. En el secundario, 31.763 de los dominios DGA están también en `dga.dom` | `comm` sobre los ficheros de `ml-data/` |
| Tres herramientas | Tres CLI más una biblioteca (`ngram.py`) y un paquete de 50 módulos; `-F` (lista de cortafuegos) no aparece en el README | `lookdga.py:44` |
| Los metadatos de cada familia describen el DGA | Hay al menos una incoherencia: suppobox dice «excepto el TLD .org» pero su `ends` es `.net`. No se han revisado los 50 a fondo | `DGAs/suppobox.py:15-17` |
| La lista `-F` es «para los próximos siete días» | Genera para hoy y los siete siguientes (ocho días) | `lookdga.py:102` |

---

## 10. Huecos y preguntas abiertas

1. **¿Se instala y carga hoy?** Hace falta crear un entorno virtual aislado y probar dos cosas:
   `pip install -r requirements.txt` con Python 3.12/3.13, y cargar `ml-data/full.pkl` con la scikit-learn
   actual. **Requiere ejecutar código y descargar paquetes: pendiente de tu permiso.** Ten en cuenta que
   cargar el pickle ya es ejecutar lo que contenga.
2. **¿Qué precisión tiene el modelo?** No hay ninguna cifra en el repositorio. Para saberlo hay que
   regenerar `main.pkl` (horas de CPU, **suposición**) y lanzar `--train full`, o al menos `--check` sobre una
   muestra conocida. ¿Guardaste los resultados del máster en algún sitio (memoria, presentación)?
3. **¿Son correctos los 50 generadores?** No hay vectores de prueba. Se podrían contrastar con las salidas de
   referencia del repositorio de Bader o con `dga.dom` para las familias que coinciden.
4. **¿De dónde sale `alexa.dom`?** El README no lo explica. Empieza por `google.com, youtube.com, tmall.com`,
   lo que encaja con un top‑500k de Alexa, pero eso es **suposición**.
5. **¿Siguen vivas las fuentes?** Alexa cerró en mayo de 2022 (hecho público, fuera del repositorio). Del feed
   `data.netlab.360.com/feeds/dga/dga.txt` no se ha comprobado si sigue publicándose (**suposición**: puede
   haber dejado de actualizarse). La lista Tranco `9Q72` probablemente sigue accesible. Comprobarlo requiere
   acceso a Internet.
6. **¿Quién es `pk <pk@gctmail.com>`?** Firma el segundo commit; el primero lo firma la cuenta del usuario.
   **Suposición:** es la misma persona desde otra máquina. Importa solo para la atribución.
7. **Licencias.** El repositorio es GPL v2 (`LICENSE`); las reglas YARA llevan CC BY‑SA 4.0; los generadores
   derivan del trabajo de Bader. No se ha verificado que las licencias sean compatibles entre sí.
8. **¿Funciona la regex del dominio de ejemplo** `uquslaigwaannie.ddns.net`? `ddns.net` está en la lista de
   sufijos (`effective_tld_names.dat:12833`), así que pasa el filtro; qué predice el modelo solo se sabe
   ejecutándolo.
9. **Relevancia a día de hoy.** Muchas de estas familias (Banjori, Tinba, Locky, Necurs…) llevan años
   inactivas, y el modelo no conoce DGAs posteriores a 2021. Para validar su utilidad actual haría falta un
   conjunto de dominios DGA recientes, que no está en el repositorio.
