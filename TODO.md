# TODO: actualización de versiones y datos

Lista de tareas para implementar `docs/CORRECCIONES.md` (correcciones C1–C13, decisiones D1–D7). El diseño ya
está acordado. Si al implementar algo choca con él, se para y se consulta, en vez de improvisar.

**Cómo usar este archivo**

- Marca cada tarea (`- [x]`) en el mismo commit que la completa.
- Si una tarea resulta más grande de lo previsto, divídela aquí antes de seguir.
- No pases a la fase siguiente sin cumplir el **criterio de aceptación** de la actual: cada fase deja el
  proyecto funcionando.
- Trabaja **una rama por fase** (`fase-N-<tema>`) y únela a `main` solo tras cumplir el criterio. La fase 1.6
  va en una rama desechable que no se une.
- «Entorno 2021» = Python 3.9 x86_64 con `requirements.txt` original (en Apple Silicon, con Rosetta: ver
  `CLAUDE.md`). «Entorno 2026» = Python 3.12/3.13 con las versiones nuevas.
- Las **pruebas se escriben antes del cambio** que cubren y deben fallar primero cuando el cambio corrige un
  error. Las de caracterización (fase 1) deben pasar con el código tal como está.
- Todo lo que publica hacia fuera (push, etiquetas, releases, solicitudes a terceros) requiere el visto bueno
  del autor en el momento de hacerlo.
- **No se sube nada a GitHub hasta terminar la actualización** (decisión del autor, 2026-10-18). Lo único
  publicado es la etiqueta `v2021` y su release (fase 0). Mientras tanto:
  - todo se hace con commits locales;
  - la CI se escribe y se prueba en local con `act`;
  - las releases nuevas se preparan como borradores locales en `release/` (ignorado por git), con su URL
    definitiva ya escrita en el manifiesto;
  - los «clones nuevos» de las verificaciones se hacen desde el repositorio local (`git clone
    /Users/xaturnon/Proyectos/DGA /tmp/dga-clon`).
  Todo se publica de una vez en la fase 7.

**Orden** (decidido con el autor; difiere del orden F0–F5 del diseño para no romper el detector entre fases):

congelar 2021 → red de pruebas → errores en el camino → datos → medir el modelo de 2021 → salto de
versiones + reentrenamiento → documentación → publicación.

---

## Fase 0 — Congelar 2021

Objetivo: que el estado de 2021 quede reproducible y descargable antes de cambiar nada (D7).

### 0.1 Repositorio al día
- [x] Hacer commit de `docs/CORRECCIONES.md` y `TODO.md` en la rama `docs/puesta-a-punto`.
- [x] Unir `docs/puesta-a-punto` a `main`, con el visto bueno del autor sobre merge directo o pull request.

### 0.2 Etiqueta y hashes
- [x] Crear la etiqueta anotada `v2021` sobre el commit `269b362`, el último con el código de 2021 sin
      documentación nueva: `git tag -a v2021 269b362 -m "Estado del máster (2021)"`.
- [x] Calcular el SHA‑256 de cada fichero que se va a archivar y guardar la lista en la carpeta temporal de
      trabajo (`shasum -a 256 …`):
  - `ml-data/full.pkl`, `full-scaler.pkl`, `tiny.pkl`, `tiny-scaler.pkl`;
  - `ml-data/tranco.ng1`–`ng4`;
  - `ml-data/{alexa,dga,mydgas,tranco-main,tranco-test2,tranco-ngram}.dom`;
  - `DGAs/wordlist/top-1m.csv`;
  - `DGAs/wordlist/effective_tld_names.dat`.

### 0.3 Release `v2021`
- [x] Subir la etiqueta: `git push origin v2021`.
- [x] Crear la release `v2021` (`gh release create v2021 …`) con los ficheros de 0.2 como assets.
- [x] Las notas de la release incluyen:
  - el entorno (Python 3.9 x86_64, `requirements.txt` de la etiqueta);
  - los comandos de instalación con Rosetta (de `CLAUDE.md`);
  - la tabla de SHA‑256;
  - un enlace a `docs/MVP.md`.
- [x] **Verificar:** descargar cada asset (`gh release download v2021 -D /tmp/v2021`) y comparar sus SHA‑256
      con la lista de 0.2.

**Aceptación de la fase 0:** la etiqueta `v2021` y su release existen en GitHub. Los assets descargados
coinciden byte a byte con los ficheros versionados. `main` contiene la documentación de la puesta a punto.
El código no ha cambiado.

---

## Fase 1 — Red de pruebas en el entorno 2021

Objetivo: fijar con pruebas lo que hoy funciona (`docs/MVP.md`), para que cualquier cambio posterior que lo
rompa se note. Todas las pruebas de esta fase pasan **sin tocar el código**.

### 1.1 Infraestructura
- [x] Crear `requirements-dev.txt` con `pytest` en una versión compatible con Python 3.9 (fijada).
- [x] Crear `pytest.ini`:
  - `testpaths = tests`;
  - marcadores `slow` (más de 30 s) y `model` (necesita `ml-data/full.pkl`);
  - opción por defecto `-m "not slow"`.
- [x] Crear `tests/conftest.py` con:
  - una función que ejecute un script del repositorio por `subprocess` con `cwd` en la raíz y el entorno
    `PYTHONDONTWRITEBYTECODE=1`, y que devuelva salida estándar, salida de error y código de salida;
  - un *fixture* `nltk_data` que apunte `NLTK_DATA` a un directorio con el corpus `brown` (descargado una
    vez fuera del repositorio);
  - un *fixture* `strip_ansi` para comparar sin códigos de color.
- [x] Documentar en `CLAUDE.md` («Entorno, ejecución y pruebas») el comando exacto:
      `pip install -r requirements-dev.txt && pytest` y `pytest -m slow` para las lentas.

### 1.2 Caracterización de `lookdga.py` (`tests/test_lookdga.py`)
- [x] `-L`: 50 líneas; la primera empieza por `banjori` y contiene `Banjori malware`.
- [x] `-m zloader -I`: contiene `Max samples per date: 32` y `Domain regular expresion: [a-y]{20}.com`.
- [x] `-m tinba -n 5 -G`: los cinco dominios exactos de `docs/MVP.md` §3, en orden.
- [x] `-d 2026-10-18 -n 3 -G`: 148 líneas de dominio (49 × 3 + 1 de tempedreve).
- [x] `-d 2026-10-18 -n 100 -C`: 5.000 líneas de datos (descartando las que empiezan por `*`) y 50 familias
      distintas en la segunda columna.
- [x] `-d 2026-10-18 -F`: 1.794 dominios, ninguno repetido (en `docs/MVP.md` salió 1.784 porque se ejecutó sin `-d`: pizd, pykspa2 y suppobox dependen de la hora).
- [x] `-D nvfowikhevmy.net`: la salida incluye `Tinba backdoor`. No se codifica el falso positivo de
      `google.com`, que es una limitación conocida y no un comportamiento que haya que conservar.
- [x] `-m noexiste -I`: contiene `Unknown malware name`.
- [x] `-m tinba -B nvfowikhevmy.net` (`slow`): contiene `tinba: Domain nvfowikhevmy.net with config 1 is in
      10 position`.

### 1.3 Instantánea y fidelidad de generadores (`tests/test_generators.py`)
- [x] Generar con el código actual `tests/data/snapshot_2026-10-18.csv`: los 3 primeros dominios de cada
      familia y semilla de `configs` para la fecha 2026-10-18 (`familia,config,posición,dominio`). Documentar
      en la cabecera del fichero con qué commit se generó.
- [x] Prueba: el código reproduce exactamente la instantánea. Es la que avisará de cualquier cambio en los
      generadores con el salto de versiones de la fase 5.
- [x] Extraer `tests/data/referencia_netlab.csv`: para las 11 variantes con confirmación externa (simda,
      ramnit, banjori, shiotob, pykspa2, tinba, fobber1, fobber2, dircrypt, pizd, vawtrak3), hasta 20
      dominios por variante presentes a la vez en `ml-data/mydgas.dom` y `ml-data/dga.dom`, con su semilla y
      su fecha.
- [x] Prueba: cada dominio de la referencia aparece entre los generados para su familia, semilla y fecha.
- [x] Prueba: las 50 variantes generan al menos un dominio sin lanzar ninguna excepción para 2026-10-18.

### 1.4 Caracterización del detector (`tests/test_check.py`, marcador `model`)
- [x] `--check` con los cinco dominios del README: `ughdnmmgdpscliraqnpl.com`, `nvfowikhevmy.net` y
      `uquslaigwaannie.ddns.net` → `DGA generated`; `google.com` y `facebook.com` → `No DGA domain`.
- [x] `-b --check nvfowikhevmy.net` (`slow`): contiene `Detected as tinba in 10 position`.

### 1.5 Caracterización de `statsdga.py` (`tests/test_statsdga.py`)
- [x] Opción 1 con 50 muestras (entrada `1\n50\n0\n`): contiene `dircrypt has a limit of 30 domains in a
      date`.
- [x] Opción 2 con 50 muestras: contiene `kraken2: 50 generated and 45 unique`.
- [x] Opción 8 con DGA (`8\n50\nn\n0\n`): la línea `All DGA:` va seguida de tres líneas de longitud media,
      mínima y máxima. Se comprueba la forma, no los valores.

### 1.6 Sondeo de compatibilidad (rama desechable `sondeo/versiones-2026`, no se une)
- [x] Crear un entorno 2026 fuera del repositorio (Python 3.13, últimas scikit-learn, pandas, numpy y nltk,
      más `pytest`).
- [x] Ejecutar en él `pytest -m "not model"` y anotar cada fallo con su traza.
- [x] En una **copia del repositorio** fuera del árbol, con `ml-data/` recortado a 10.000 líneas por fichero
      `.dom`:
  - ejecutar `--ngram`, `--main`, `--train full` y `--check`;
  - anotar cada error de API (pandas 3.0, numpy 2, nltk 3.9) con su archivo y línea.
- [x] Medir el tiempo de `--ngram`, `--main` y `--train full` con 10.000 dominios y extrapolar a los
      tamaños reales (unos 3 M en `--main`).
- [x] Anotar los resultados (lista de roturas, tiempos, extrapolación) en un anexo «Resultados del sondeo» al
      final de `docs/CORRECCIONES.md`, sin cambiar sus decisiones. Hacer commit de ese anexo en la rama de
      la fase 1.

### 1.7 CI en el entorno 2021
- [x] Crear `.github/workflows/tests.yml`:
  - `ubuntu-22.04`, Python 3.9;
  - `pip install -r requirements.txt -r requirements-dev.txt`;
  - caché del corpus `brown` (`python -m nltk.downloader -d ~/nltk_data brown`);
  - `pytest` (sin `slow`).
- [x] Instalar `act` en la máquina del autor (`brew install act`; Docker ya está en `/usr/local/bin/docker`),
      con su visto bueno.
- [x] **Verificar en local:** `act -j <trabajo> --container-architecture linux/amd64` ejecuta el workflow y
      pasa en verde. La comprobación en GitHub queda para la fase 7.

**Aceptación de la fase 1:** `pytest` y `pytest -m slow` pasan en el entorno 2021 sin haber cambiado el
código. El workflow de CI pasa en verde en `act`. El anexo del sondeo está escrito, con la lista de roturas del entorno 2026 y la
estimación del tiempo de reentrenamiento.

---

## Fase 2 — Errores en el camino (entorno 2021)

Objetivo: que el detector y el corpus den resultados fiables antes de usarlos para verificar datos y modelos
(C12, C13, C6, C9, C11).

### 2.1 `--check` empareja veredictos y dominios (C12)
- [ ] Extraer de `testdomains()` (`detectdga.py:642-726`) una función de clasificación que reciba la lista de
      dominios, el modelo, el escalador, el diccionario de n-gramas y el silabeador. Debe devolver, por cada
      dominio de entrada, el dominio, el veredicto (o ninguno) y el motivo del descarte. `testdomains()` solo
      imprime.
- [ ] Escribir antes en `tests/test_check.py` las pruebas con un modelo falso (un objeto con `predict` que
      devuelve un veredicto distinto por posición) y un escalador identidad. Deben fallar con el código
      actual:
  - `[bbc.com, google.com, X]`: cada veredicto va con su dominio y `bbc.com` sale como descartado («SLD of 3
    characters or fewer»);
  - `[bbc.com]`: termina sin excepción, informa del descarte y no llama a `predict`;
  - `[GOOGLE.COM]`: se evalúa como `google.com`;
  - un dominio con sufijo desconocido: sale como descartado («unknown suffix»).
- [ ] Implementar el emparejamiento: los veredictos se asocian por dominio y no por índice (`:709-710`, `:713`,
      `:718`).
- [ ] Implementar la lista de descartados con su motivo, impresa después de los veredictos.
- [ ] Si no queda ningún dominio, no llamar a `sc.transform` (`:698`).
- [ ] Pasar la entrada a minúsculas antes de `sldtld()`. El tratamiento de `www.` y de los subdominios **no
      cambia**.
- [ ] **Verificar regresiones:** la prueba de caracterización 1.4 (los cinco dominios del README) sigue
      pasando con los mismos veredictos.

### 2.2 `-C` deja la salida estándar limpia (C13)
- [ ] Escribir antes en `tests/test_lookdga.py`: `lookdga.py -m banjori -n 2 -C` → todas las líneas de la
      salida estándar cumplen `^[^,]+,[^,]+,[^,]*,\d{4}-\d{2}-\d{2}$`, y las líneas de estado aparecen en la
      salida de error. Debe fallar.
- [ ] En `dga.create()` (`dga.py:238`, `:283`), imprimir las dos líneas de estado en `sys.stderr`.
- [ ] Mantener el filtro de `*` de `createtestdataset()` (`detectdga.py:410`) para seguir leyendo los
      `mydgas.dom` antiguos. Añadir un comentario que lo explique.
- [ ] Actualizar la prueba 1.2 de `-C`: ya no hace falta descartar las líneas con `*`.
- [ ] **Verificar regresiones:** las pruebas de `-G`, `-I`, `-F` y `-L` siguen pasando sin cambios, y
      `statsdga.py`, que usa `dga.create()` con `main=False`, también.

### 2.3 `--secondary` usa el fichero que existe (C6)
- [ ] Añadir a `tests/conftest.py` un *fixture* `repo_tmp`: un directorio temporal con un enlace a `DGAs/` y
      un `ml-data/` con ficheros mínimos (`tranco.ng1-4` reales, `tranco-test2.dom` de 20 líneas,
      `mydgas.dom` de 20 líneas).
- [ ] Escribir antes en `tests/test_cli.py`: `detectdga.py --secondary` en `repo_tmp` crea
      `ml-data/secondary.pkl` y no imprime `not found`. Debe fallar.
- [ ] Definir en `detectdga.py` una sola constante con la ruta `ml-data/tranco-test2.dom` y usarla en
      `createtestdataset()` (`:356`) y en `main()` (`:775-778`).

### 2.4 Comprobación completa del diccionario (C9)
- [ ] Escribir antes en `tests/test_cli.py`: en `repo_tmp`, al quitar `tranco.ng2`, `ng3` o `ng4` por turno,
      `--main` termina con un mensaje que nombra el fichero que falta y con un código de salida distinto
      de 0. Debe fallar.
- [ ] Corregir `checktranco()` (`detectdga.py:729-734`) para comprobar los cuatro ficheros.
- [ ] Corregir `loadngram()` (`:203-214`): en lugar de devolver `None` en silencio, informar de qué fichero
      falló y por qué.

### 2.5 Nada de red al importar (C11)
- [ ] Crear el módulo `nlpdata.py` con una función que compruebe el corpus `brown` (`nltk.data.find`) y, si
      falta, termine con un mensaje que indique el comando de instalación
      (`python -m nltk.downloader -d <dir> brown`, más `NLTK_DATA`).
- [ ] Escribir antes `tests/test_offline.py`. Las dos pruebas deben fallar:
  - con `nltk.download` sustituido por una función que falla, importar `detectdga` no la llama;
  - `statsdga.py` ejecutado con un `NLTK_DATA` vacío y la opción 8 no intenta descargar y muestra el mensaje.
- [ ] Quitar la descarga a nivel de módulo de `detectdga.py:20-23` y `statsdga.py:10-13`.
- [ ] Llamar a la comprobación justo antes de cada `LegalitySyllableTokenizer(brown.words())`: en
      `detectdga.py`, `createmaindataset`, `createtestdataset`, `createalexadataset` y `testdomains`; en
      `statsdga.py`, `syll`.
- [ ] Actualizar la sección «Install» de `README.md` (inglés, en la voz del autor): el corpus se descarga con
      el comando anterior y la primera ejecución ya no lo hace sola.

### 2.6 Verificación de la fase
- [ ] Ejecutar `pytest` y `pytest -m slow` en el entorno 2021: todo en verde.
- [ ] A mano: ejecutar los ejemplos de `README.md` de `lookdga.py` y `detectdga.py --check` y comparar con
      `docs/MVP.md`.
- [ ] Quitar de `README.md` las notas «Known issue (2026)» que resuelve esta fase (desalineación y lista vacía
      de `--check`, `--secondary`). Conservar el texto original del autor.

**Aceptación de la fase 2:**
- en `--check`, cada veredicto aparece junto a su dominio y los descartes se explican;
- `-C` produce un CSV limpio;
- `--secondary` funciona;
- la falta de un fichero del diccionario se informa;
- importar no descarga nada;
- todas las pruebas de la fase 1 siguen pasando.

---

## Fase 3 — Datos: manifiesto, releases y fuentes nuevas

Objetivo: que los datos pesados salgan de git y se descarguen verificados, y que los datos nuevos estén
obtenidos (C8, C7, C3, C4). **El detector sigue funcionando con el modelo de 2021**, descargado de `v2021`.

### 3.1 Manifiesto y descarga verificada (C8)
- [ ] Definir el formato de `ml-data/MANIFEST`: TSV con las columnas `fichero`, `url`, `tamaño`, `sha256`,
      `fuente`, `licencia` y `juego` (`2021` | `2026`). Documentarlo en una cabecera comentada.
- [ ] Rellenar el manifiesto con los assets de `v2021` (hashes de 0.2), todos en el juego `2021`.
- [ ] Crear `fetchdata.py` en la raíz, solo con biblioteca estándar (`urllib`, `hashlib`, `argparse`):
  - descarga a `ml-data/` los ficheros del manifiesto;
  - verifica cada SHA‑256 y borra el fichero si no coincide;
  - salta los que ya existen y están verificados;
  - opción `--nltk` que lanza el comando de `nlpdata.py`;
  - opción `--desde <directorio>`, que copia los ficheros desde un directorio local en lugar de descargarlos,
    con la misma verificación de SHA‑256. Es lo que permite probar los juegos nuevos antes de publicarlos.
- [ ] Escribir `tests/test_fetchdata.py` con un servidor `http.server` local:
  - un fichero correcto se descarga y se verifica;
  - un hash incorrecto da un código de salida distinto de 0 y no deja el fichero;
  - una segunda ejecución no descarga nada;
  - `--desde` con un fichero correcto lo instala, y con uno alterado falla.
- [ ] Escribir antes en `tests/test_cli.py`: con `ml-data/` vacío en `repo_tmp`, `--check google.com` termina
      con un mensaje que dice que hay que ejecutar `python fetchdata.py` y con un código distinto de 0. Debe
      fallar.
- [ ] Implementar ese mensaje en `detectdga.py`: comprobar los ficheros necesarios antes de cargarlos en
      `testdomains`, `testsecdata` y `traindata`.
- [ ] `.gitignore`: añadir `ml-data/*` y `!ml-data/MANIFEST`.
- [ ] Retirar del índice los ficheros de `ml-data/` salvo el manifiesto: `git rm --cached ml-data/*.pkl
      ml-data/*.dom ml-data/tranco.ng*`. Siguen en `v2021`.
- [ ] Actualizar la CI (1.7): `python fetchdata.py` con caché de `ml-data/` indexada por el hash de
      `ml-data/MANIFEST`. Probarlo con `act`; la caché real de GitHub solo se comprueba en la fase 7.
- [ ] **Verificar:** en un clon nuevo hecho desde el repositorio local, en un directorio temporal, que descarga
      los assets de `v2021` (ya publicados), `python fetchdata.py --nltk` seguido de
      `pytest -m "model or not model"` pasa, y `--check` con los cinco dominios del README da los mismos
      veredictos.
- [ ] Actualizar `README.md` («Install»): el paso `python fetchdata.py --nltk` tras instalar las dependencias,
      y que clonar ya no basta.
- [ ] Actualizar `CLAUDE.md`:
  - regla 13: los ficheros de `ml-data/` se descargan; antes de regenerarlos, comprobar el juego con el
    manifiesto;
  - regla 15: los datos se cambian a través del manifiesto, no a mano;
  - mapa de directorios.

### 3.2 Lista de sufijos nueva, preparada y sin activar (C7)
- [ ] Hacer configurable la ruta de `loadetlds()` (`detectdga.py:28-66`), con la ruta actual por defecto,
      para poder probar con otras listas.
- [ ] Escribir `tests/test_sldtld.py`, parametrizado por lista:
  - sufijos de varios niveles (`example.co.uk`);
  - sufijos privados (`uquslaigwaannie.ddns.net`);
  - SLD de 3 caracteres (`bbc.com` → descartado);
  - un sufijo presente solo en la lista nueva: aceptado con la nueva y rechazado con la de 2021.
- [ ] Descargar `https://publicsuffix.org/list/public_suffix_list.dat` y anotar fecha y SHA‑256.
- [ ] Añadirla al juego `2026` del manifiesto como `ml-data/public_suffix_list.dat`. **No sustituir todavía**
      `DGAs/wordlist/effective_tld_names.dat`: el modelo de 2021 necesita la lista de 2021 (ver 5.3).

### 3.3 Dominios legítimos actuales (C3)
- [ ] Elegir la lista Tranco más reciente en el momento de implementarlo
      (`https://tranco-list.eu/api/lists/date/latest`) y anotar su ID. La comprobada en el diseño es la
      `8PX8V`.
- [ ] Descargar la lista **completa** (`https://tranco-list.eu/list/<ID>/full`) como `ml-data/tranco.csv`.
- [ ] Generar `tranco-main.dom`, `tranco-test2.dom` y `tranco-ngram.dom` con los tres `sed` del README,
      quitando los `\r`.
- [ ] Escribir `tests/test_data.py` (marcador `slow`): los tres ficheros no comparten ningún dominio, y sus
      tamaños y hashes coinciden con el manifiesto.
- [ ] Añadir al juego `2026` del manifiesto `tranco.csv` y los tres `.dom`, con el ID Tranco en la columna
      `fuente`.
- [ ] Descargar Cisco Umbrella top‑1M (`http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip`),
      descomprimirlo como `ml-data/umbrella-raw.csv` y anotar la fecha y el SHA‑256 en el manifiesto. La
      reducción a dominios registrables se hace en la fase 4.
- [ ] `statsdga.py`: cambiar las seis lecturas de `DGAs/wordlist/top-1m.csv` (`statsdga.py:110,145,183,220,
      260,543`) por `ml-data/tranco.csv`, que tiene el mismo formato `rango,dominio`, definido como una
      constante. Cambiar los textos «Alexa top million» del menú por «Tranco».
- [ ] Actualizar la prueba 1.5 si cambia algún valor que dependa de la lista. La opción 1 no depende de ella.
- [ ] Retirar `DGAs/wordlist/top-1m.csv` del árbol (`git rm`); sigue en `v2021`. `checkdomains()`, que es
      código muerto, también lo lee: añadir un comentario que lo señale.

### 3.4 Dominios DGA (C4)
- [ ] Mantener `ml-data/dga.dom` de 2021 en **los dos** juegos del manifiesto, con el mismo hash y la fuente
      «360 Netlab, 2021».
- [ ] Descargar el dataset `harpomaxx/dga-detection` de Hugging Face. Comprobar su formato y quedarse solo
      con las filas etiquetadas como DGA.
- [ ] Convertirlo a `ml-data/hf-dga.dom` con el formato de `dga.dom` (`familia<TAB>dominio`). Anotar en el
      manifiesto la revisión del dataset, el SHA‑256 y la licencia CC BY 2.0.
- [ ] Regenerar el corpus propio, ya limpio gracias a 2.2: `python lookdga.py -d 2026-10-18 -n 3000 -C >
      ml-data/mydgas.dom`. Anotar la fecha usada en el manifiesto (juego `2026`).
- [ ] **Licencias:** comprobar y anotar en la columna `licencia` si se pueden redistribuir:
  - la lista Tranco;
  - los términos de Cisco Umbrella;
  - la CC BY 2.0 de Hugging Face (exige atribución);
  - el feed de 360 Netlab.
  Si alguna no permite redistribuir, ese fichero **no se sube** como asset. El manifiesto lleva entonces la
  URL original y `fetchdata.py` lo descarga de su fuente.
- [ ] **Fuera del código:** enviar a Fraunhofer FKIE la solicitud de acceso a DGArchive. Anotar la fecha y la
      respuesta en `docs/FUTURE.md` §1.2.1.

### 3.5 Borrador local de la release de datos 2026
- [ ] Elegir el nombre definitivo de la release (propuesta: `datos-2026`).
- [ ] Añadir `release/` a `.gitignore`.
- [ ] Copiar a `release/datos-2026/` los ficheros del juego `2026` que se puedan redistribuir (3.4), junto
      con un `notas.md` con su procedencia, licencias y SHA‑256. **No se publica**: eso se hace en la fase 7.
- [ ] Rellenar en el manifiesto sus URLs definitivas
      (`https://github.com/dpgon/DGA/releases/download/datos-2026/<fichero>`). Los ficheros que no se
      redistribuyen llevan la URL de su fuente.
- [ ] `fetchdata.py --juego 2026` instala el juego de datos nuevo; hasta la fase 7, con
      `--desde release/datos-2026`. Por defecto, los ficheros del **modelo** y del diccionario siguen siendo
      los de `2021` hasta la fase 5.
- [ ] **Verificar:** en un clon nuevo hecho desde el repositorio local, `fetchdata.py` (por defecto, que
      descarga de `v2021`) y `fetchdata.py --juego 2026 --desde <ruta>/release/datos-2026` instalan y
      verifican todo, y las pruebas de las fases 1–2 pasan.

**Aceptación de la fase 3:**
- el árbol de trabajo ya no contiene ficheros pesados;
- un clon nuevo con `python fetchdata.py --nltk` deja el detector de 2021 funcionando con los mismos
  veredictos;
- los datos nuevos (Tranco con ID, Umbrella, Hugging Face, corpus propio, lista de sufijos) están descargados,
  verificados y registrados en el manifiesto con su licencia;
- la solicitud a DGArchive está enviada.

---

## Fase 4 — Evaluación independiente y métricas del modelo de 2021

Objetivo: que ningún conjunto de evaluación comparta dominios con el entrenamiento y publicar por primera vez
cuánto acierta el modelo de 2021 (C5, y la parte de evaluación de C3 y C4).

### 4.1 Exclusión de lo que hay en el entrenamiento (C5)
- [ ] Escribir antes `tests/test_datasets.py` con ficheros pequeños en `repo_tmp` que tengan solapes
      conocidos, en mayúsculas y en minúsculas. Debe fallar:
  - el conjunto secundario y el de Umbrella no contienen ningún dominio ni SLD de `tranco-main.dom`,
    `tranco-ngram.dom` ni `dga.dom`;
  - el recuento de excluidos que se imprime es el esperado.
- [ ] Implementar en `detectdga.py` una función que cargue en un conjunto los dominios y SLD de entrenamiento
      (en minúsculas, dominio registrable según `sldtld()`), y usarla en `createtestdataset()` y en la
      construcción de Umbrella.
- [ ] Imprimir el recuento de excluidos y guardarlo en `ml-data/<conjunto>.json`, que se fundirá en los
      metadatos de la fase 5.
- [ ] Conjunto secundario con dos orígenes DGA: `mydgas.dom` y `hf-dga.dom`. La columna `family` lleva el
      prefijo de origen (`own:` / `hf:`) para **no cambiar las 28 columnas** del esquema.

### 4.2 Conjunto Umbrella en lugar de Alexa (C3)
- [ ] Escribir antes la prueba de la reducción: a partir de un `umbrella-raw.csv` pequeño con subdominios
      (`a.b.example.co.uk`), se obtienen dominios registrables únicos (`example.co.uk`).
- [ ] Sustituir `createalexadataset()` (`detectdga.py:460-517`) por la construcción del conjunto Umbrella:
      reducción a dominio registrable, exclusión de 4.1 y salida en `ml-data/umbrella.pkl`.
- [ ] Opciones nuevas `--umbrella` y `--test_umbrella`. `--alexa` y `--test_alexa` se mantienen como alias que
      avisan de que están obsoletas.
- [ ] Prueba de los alias en `tests/test_cli.py`.

### 4.3 Informe de evaluación por origen
- [ ] Escribir antes la prueba: `testsecdata()` (`detectdga.py:584-639`), con un DataFrame pequeño y un modelo
      falso, imprime métricas totales y por origen (`own`, `hf`, `tranco`, `umbrella`).
- [ ] Implementar el desglose por origen con el prefijo de `family`.

### 4.4 Medir el modelo de 2021 (entorno 2021)
- [ ] Construir `secondary.pkl` y `umbrella.pkl` con los datos 2026, el diccionario de n-gramas de 2021 y la
      lista de sufijos de 2021, que son los recursos del modelo de 2021.
- [ ] Ejecutar `--test_secondary full`, `--test_secondary tiny`, `--test_umbrella full` y `--test_umbrella
      tiny`, y guardar las salidas completas.
- [ ] Anotar los tiempos de construcción y de evaluación.
- [ ] Escribir en `docs/MVP.md` una sección nueva, «Métricas del modelo de 2021, medidas en 2026», con la
      matriz de confusión, la precisión, la exhaustividad y la exactitud por conjunto y por origen, el
      número de excluidos y los IDs de los datos usados.
- [ ] Sustituir en `README.md` la nota sobre `--test_alexa` por un enlace a esas métricas.

**Aceptación de la fase 4:**
- las pruebas demuestran que los conjuntos de evaluación no se solapan con el entrenamiento;
- `--umbrella` sustituye a `--alexa`, con alias;
- las métricas del modelo de 2021 sobre conjuntos limpios están publicadas en `docs/MVP.md`;
- todo lo anterior sigue pasando.

---

## Fase 5 — Salto de versiones y reentrenamiento

Objetivo: el proyecto en Python 3.12/3.13 con las versiones actuales y un modelo nuevo, guardado sin pickle
y con metadatos (C1, C2, C10, y la activación de C7). **Toda la fase va en una sola rama**, que no se une
hasta que el modelo nuevo funcione: en medio, el modelo de 2021 no carga.

Depende de: el anexo del sondeo (1.6), las fases 2–4 y los datos del juego `2026`.

### 5.1 Requisitos y entorno (C1)
- [ ] Reescribir `requirements.txt` con dependencias **directas** y cotas inferiores validadas en el sondeo:
  - scikit-learn, pandas, numpy, nltk y skops;
  - quitar `dnspython`;
  - quitar las transitivas.
- [ ] Hacer perezoso el import de `dns.resolver` (`detectdga.py:10`): moverlo dentro de `existdomain()`
      (código muerto) para que importar `detectdga` no exija `dnspython`. Añadir un comentario que remita a
      `docs/FUTURE.md` §1.1.10.
- [ ] Generar `requirements-lock.txt` con `uv pip compile requirements.txt --universal --python-version 3.12
      -o requirements-lock.txt`.
- [ ] Actualizar `requirements-dev.txt` a un `pytest` actual.
- [ ] Corregir las roturas y avisos del anexo del sondeo (`docs/CORRECCIONES.md`). No se encontró ninguna
      rotura de API de pandas 3.0, numpy 2 ni scikit-learn 1.9; los `df.drop(..., inplace=True)` funcionan. La
      rotura n.º 1 (`dnspython`) es la casilla anterior; la n.º 3 (`ResourceWarning`) se resuelve en 5.2. Queda:
  - [ ] `DGAs/pizd.py:21`: sustituir `datetime.utcfromtimestamp(0)` (obsoleto) por un equivalente con zona
        horaria que dé **el mismo resultado**. Lo comprueban la instantánea (1.3) y la referencia de Netlab de
        pizd.
- [ ] Si al empezar la fase hay versiones más nuevas que las del sondeo, repetir el sondeo de 1.6 con ellas y
      añadir aquí una casilla por cada rotura nueva.
- [ ] **Verificar regresiones:** en el entorno 2026, `pytest -m "not model"` pasa. En particular, la
      instantánea de generadores (1.3) es **idéntica**: el salto de versiones no debe cambiar ningún dominio
      generado.

### 5.2 Persistencia segura y metadatos (C2, C10)
- [ ] `ngram.py`: sustituir `to_pickle`/`read_pickle` (`ngram.py:45-55`) por un formato de texto: un CSV por
      orden (`tranco.ng1.csv` … `ng4.csv`, columnas `ngrama,valor`).
- [ ] Probar en `tests/test_ngram.py`:
  - guardar y cargar conserva todos los valores;
  - `getall()` da los mismos resultados que con el diccionario de 2021 convertido;
  - n-gramas con comillas no rompen nada.
- [ ] Sustituir el acceso con `eval` de `_checkdom()` (`ngram.py:61-62`) por un acceso directo, dado que se
      cambia el formato. La prueba anterior lo cubre.
- [ ] `detectdga.py`:
  - guardar modelo y escalador con `skops` en `traindata()` (`:564,571`);
  - cargarlos con `skops` y una lista explícita de tipos de confianza en `testsecdata()` (`:623,629`) y
    `testdomains()` (`:695,701`);
  - nombres `ml-data/{variante}.skops` y `{variante}-scaler.skops`.
- [ ] Escribir el fichero de metadatos `ml-data/{variante}.json` al entrenar, con:
  - versiones de Python y de las librerías;
  - fecha;
  - ID Tranco y fuentes DGA con su SHA‑256;
  - SHA‑256 del diccionario de n-gramas y de la lista de sufijos;
  - hiperparámetros;
  - recuentos de exclusión (4.1);
  - métricas.
- [ ] Al cargar, comprobar los SHA‑256 del diccionario y de la lista de sufijos contra los metadatos. Si no
      coinciden, terminar con un mensaje que diga cuál no coincide.
- [ ] Escribir `tests/test_model.py`:
  - carga sin `pickle`, con un modelo pequeño entrenado en la prueba;
  - un diccionario con el hash alterado se rechaza;
  - un tipo que no está en la lista de confianza se rechaza.
- [ ] C10: `n_jobs=-1` en `RandomForestClassifier` (`detectdga.py:567`) y fijar `model.n_jobs` al cargar.
      Probarlo en `tests/test_model.py`.

### 5.3 Activar la lista de sufijos nueva (C7)
- [ ] Sustituir `DGAs/wordlist/effective_tld_names.dat` por la lista de 3.2. Anotar su fecha y su SHA‑256 en
      el manifiesto. La de 2021 sigue en `v2021`.
- [ ] Añadir sobre los 154 sufijos manuales (`detectdga.py:31-58`) un comentario que diga de dónde salen
      («extraídos de Alexa top 1M, 2021»).
- [ ] Actualizar `tests/test_sldtld.py`: la lista por defecto es la nueva.

### 5.4 Reentrenamiento
- [ ] Copiar `ml-data/` fuera del repositorio antes de regenerar nada (`CLAUDE.md`, regla 13).
- [ ] `--ngram` con el `tranco-ngram.dom` de 2026, en el formato nuevo de 5.2.
- [ ] `--main`, con `tranco-main.dom` de 2026 y `dga.dom` de 2021.
- [ ] `--secondary` y `--umbrella`, con la exclusión de 4.1.
- [ ] Escribir la **prueba de paridad de características** en `tests/test_model.py` (`slow`): para 100 filas
      de `main.pkl`, el vector que calcula la función de clasificación de 2.1 para su dominio es idéntico a la
      fila.
- [ ] `--train full` y `--train tiny`, con los hiperparámetros de 2021 (`detectdga.py:555,567`). Anotar el
      tiempo.
- [ ] `--test_secondary` y `--test_umbrella` con `full` y `tiny`, desglosados por origen.
- [ ] Comparar con las métricas de 2021 de la fase 4.
- [ ] **Verificar a mano**, antes de publicar:
  - el ejemplo `--check` del README con los cinco dominios: anotar los resultados nuevos;
  - `google.com`, `facebook.com` y `wikipedia.org` dan `No DGA domain`;
  - los dominios de `tests/data/referencia_netlab.csv` dan mayoritariamente `DGA generated`;
  - las métricas son razonables frente a las de 2021. Si caen mucho, parar y analizar antes de publicar.
- [ ] Actualizar la prueba 1.4 con los veredictos esperados del modelo nuevo y añadir el conjunto de
      referencia de C2 (umbral de aciertos, no igualdad exacta).
- [ ] Preparar el borrador local de la release del modelo en `release/modelo-2026/` (nombre definitivo a
      elegir al implementarlo): `full.skops`, `full-scaler.skops`, `full.json`, el equivalente de `tiny`,
      `tranco.ng*.csv` y un `notas.md` con las métricas y los SHA‑256. **No se publica** hasta la fase 7.
- [ ] Actualizar el manifiesto con sus URLs definitivas. El juego por defecto pasa a `2026`; `2021` queda como
      juego histórico.
- [ ] **Verificar:** en un clon nuevo hecho desde el repositorio local, `fetchdata.py --desde
      <ruta>/release/modelo-2026` y `--desde <ruta>/release/datos-2026` dejan `--check` funcionando con el
      modelo nuevo.

### 5.5 CI en las versiones nuevas
- [ ] Sustituir el trabajo de Python 3.9 de `.github/workflows/tests.yml` por una matriz {`ubuntu-latest`,
      `macos-14` (arm64), `windows-latest`} × {3.12, 3.13}:
  - `pip install -r requirements-lock.txt -r requirements-dev.txt`;
  - `python fetchdata.py --nltk` con caché;
  - `pytest`.
- [ ] **Verificar Linux en local:** `act` ejecuta los trabajos de Ubuntu con 3.12 y 3.13 en verde. `act` solo
      ejecuta contenedores Linux.
- [ ] **Verificar macOS arm64 en local:** en la máquina del autor, sin Rosetta, con 3.12 y 3.13:
      `pip install -r requirements-lock.txt -r requirements-dev.txt`, `fetchdata.py --desde …` y `pytest`
      pasan.
- [ ] **Windows:** no se puede verificar en local. Queda para la fase 7, con estas comprobaciones:
  - las rutas `ml-data/…` y `DGAs/wordlist/…` funcionan;
  - los colores ANSI no rompen las pruebas;
  - los generadores con `ctypes` dan la instantánea de 1.3;
  - la instantánea se reproduce con `TZ=UTC` aunque Windows no tenga `time.tzset()` (ver `tests/conftest.py`).  Si no, fijar la zona horaria en el workflow.

**Aceptación de la fase 5:**
- en Python 3.12 y 3.13, en Linux (`act`) y en macOS arm64 (local), la instalación con
  `requirements-lock.txt` y `fetchdata.py` funciona sin emulación, y `pytest` pasa. Windows queda pendiente
  de la fase 7;
- el modelo nuevo se carga sin `pickle`, con metadatos y hashes verificados;
- las métricas sobre conjuntos limpios están medidas y comparadas con las de 2021;
- la instantánea de generadores no ha cambiado.

---

## Fase 6 — Documentación

Objetivo: que cada documento diga lo que hay (`docs/CORRECCIONES.md`, «Documentación que hay que
actualizar»). En la voz y el idioma de cada documento: `README.md` en inglés, el resto en español.

### 6.1 `README.md`
- [ ] «Install»: Python 3.12/3.13, `pip install -r requirements-lock.txt` (o `requirements.txt`),
      `python fetchdata.py --nltk`, ejecutar desde la raíz. Conservar la frase original del autor y ajustar
      su nota «Known issue» para que diga que ya está resuelto, con la versión.
- [ ] Quitar las notas «Known issue (2026)» resueltas: instalación, Alexa contaminada y CSV de `-C`.
      Conservar las no resueltas: patrones laxos, ventana de la fuerza bruta y la opción 9 de `statsdga.py`.
- [ ] Ajustar la nota de `statsdga.py`: ahora usa Tranco. Conservar la frase original del autor sobre
      Alexa, con la nota al lado.
- [ ] `detectdga.py`: documentar `--umbrella`/`--test_umbrella` y los alias. Explicar que los datos se
      descargan con `fetchdata.py`, y que las instrucciones de Tranco y Netlab sirven para reconstruirlos.
- [ ] Resultados nuevos del ejemplo `--check` (5.4) y una tabla de métricas 2021 frente a 2026.
- [ ] «Tests»: `pip install -r requirements-dev.txt`, `pytest`, `pytest -m slow`, y qué cubre cada fichero de
      `tests/`.
- [ ] «Credits»: Tranco (con el ID de la lista), Cisco Umbrella, Hugging Face `harpomaxx/dga-detection` (CC BY
      2.0, con la atribución que exige) y 360 Netlab (datos de 2021).
- [ ] «Status (2026)»: reescribir según el estado real tras la fase 5.

### 6.2 `docs/`
- [ ] `docs/MVP.md`:
  - §0 Instalación;
  - §8–9 Detector, con criterios verificados de nuevo;
  - sacar `--secondary` y la comprobación del diccionario de «A medias»;
  - métricas 2026 junto a las de 2021;
  - «Definición de terminado» (pruebas y CI que existen ahora).
- [ ] `docs/ARCHITECTURE.md`:
  - §2 Stack (versiones nuevas, `skops`, sin `dnspython`, `pytest`);
  - §3 Estructura (`tests/`, `fetchdata.py`, `nlpdata.py`, `ml-data/MANIFEST`);
  - §4 Modelo de datos (formatos `.skops`, `.json`, `ng*.csv`, manifiesto, juegos 2021/2026);
  - §5.3 Red (sin descarga al importar; descarga en `fetchdata.py`);
  - §8 Pruebas (comandos y cobertura);
  - §9 Distribución (releases);
  - §11 decisiones D1–D7;
  - §12 marcar la deuda resuelta (1, 2, 3, 4 en parte, 5, 12, 14, 15, 16).
- [ ] `docs/FUTURE.md`: marcar como hechas las partes de 1.1.1, 1.1.2, 1.1.3 (alineación), 1.1.6, 1.1.7 y
      1.1.9 (CSV de `-C`) que cubre esta corrección. Dejar 1.2.1 con el estado de DGArchive.
- [ ] `docs/ESTUDIO.md`: añadir al principio una nota que diga que es la foto de 2021 y remita a
      `docs/CORRECCIONES.md`. No cambiar nada más.
- [ ] `docs/CORRECCIONES.md`: añadir el estado «Implementado» con la fecha y la versión, y las desviaciones
      respecto al diseño, si las hubo.

### 6.3 `CLAUDE.md`
- [ ] «Entorno, ejecución y pruebas»:
  - quitar Rosetta y Python 3.9 como entorno de trabajo, que queda como entorno de `v2021`;
  - añadir `requirements-lock.txt`, `fetchdata.py --nltk` y los comandos de `pytest`.
- [ ] Reglas:
  - 5: hashes en los metadatos;
  - 6: actualizar librerías obliga a reentrenar, aunque ahora con `skops`;
  - 7: no hay pickles; `skops` con tipos de confianza;
  - 13: regenerar los datos y publicar una release nueva;
  - 15: el manifiesto.
- [ ] Mapa de directorios: `tests/`, `fetchdata.py`, `nlpdata.py`, `ml-data/MANIFEST`.

### 6.4 Verificación de la documentación
- [ ] Ejecutar uno por uno los comandos de `README.md` y `CLAUDE.md` en un clon nuevo con el entorno 2026 y
      comprobar que dan lo que dicen.
- [ ] Comprobar que todos los enlaces internos de `README.md` y de `docs/` apuntan a secciones que existen.

**Aceptación de la fase 6:** cada afirmación de `README.md`, `CLAUDE.md` y `docs/` sobre el comportamiento
está verificada o marcada como no verificada (`CLAUDE.md`, regla 17), y los comandos documentados funcionan
en un clon nuevo.

---

## Fase 7 — Publicación

Objetivo: publicar de una vez la actualización completa y comprobar en GitHub lo que no se pudo comprobar en
local. Cada paso requiere el visto bueno del autor en el momento de hacerlo.

### 7.1 Antes de publicar
- [ ] Revisar con el autor la lista de lo que se va a publicar:
  - los commits de `main` (`git log origin/main..main`);
  - las dos releases de `release/`, con sus notas;
  - las etiquetas nuevas.
- [ ] Comprobar que ningún fichero de más de 100 MB entra en los commits (`git rev-list --objects
      origin/main..main` + `git cat-file --batch-check`) y que `release/` y `ml-data/*` no están versionados.

### 7.2 Releases
- [ ] Publicar la release de datos (`gh release create datos-2026 …`) con los ficheros y las notas de
      `release/datos-2026/`.
- [ ] Publicar la release del modelo (`gh release create modelo-2026 …`) con `release/modelo-2026/`.
- [ ] **Verificar:** descargar cada asset (`gh release download`) y comparar su SHA‑256 con
      `ml-data/MANIFEST`.

### 7.3 Código
- [ ] `git push origin main`, más la etiqueta de versión de la actualización si el autor decide crearla.
- [ ] **Verificar la CI en GitHub:** la matriz completa de 5.5 pasa en verde, **incluido Windows**, con las
      comprobaciones de Windows de 5.5.
- [ ] Si Windows falla: corregirlo en una rama, verificarlo en la CI de GitHub (ya se puede subir) y unirlo
      a `main`.
- [ ] Comprobar que la caché de `ml-data/` de la CI funciona: la segunda ejecución no vuelve a descargar.

### 7.4 Comprobación final
- [ ] En un clon nuevo **desde GitHub**, sin `--desde`: instalar con `requirements-lock.txt`,
      `python fetchdata.py --nltk`, `pytest` y el ejemplo `--check` del README.
- [ ] Comprobar que el enlace de las notas de `v2021` a `docs/MVP.md` en `main` funciona.
- [ ] Borrar los borradores locales de `release/`, una vez verificadas las releases publicadas.

**Aceptación de la fase 7:**
- `main`, las releases de datos y de modelo y sus assets están en GitHub y sus hashes coinciden;
- la CI pasa en verde en las tres plataformas;
- un clon nuevo desde GitHub funciona siguiendo solo el README.

---

## Dependencias entre fases

| Fase | Depende de | Motivo |
|---|---|---|
| 1 | 0 | Las pruebas se escriben sobre `main` con la documentación unida |
| 2 | 1 | Las pruebas de caracterización son las que detectan regresiones |
| 3 | 0, 2 | El manifiesto apunta a los assets de `v2021`; `mydgas.dom` se regenera con el CSV limpio (2.2) |
| 4 | 2, 3 | Necesita `--secondary` (2.3) y los datos de 2026 (3.3, 3.4) |
| 5 | 1.6, 2, 3, 4 | Las roturas de API salen del sondeo; las métricas de 2021 (4.4) son la base de comparación |
| 6 | 5 | Documenta el estado final. Las notas del README de cada fase ya se actualizan en su fase |
| 7 | 6 | Solo se publica cuando todo está terminado y documentado (decisión del autor) |
| — | Externa: DGArchive | No bloquea ninguna fase; su respuesta solo se anota (3.4) |

## Cobertura del diseño

| Punto de `docs/CORRECCIONES.md` | Lo entrega |
|---|---|
| D7 Etiqueta `v2021` y retirada de los ficheros de 2021 | 0.2, 0.3, 3.1, 3.3 (`top-1m.csv`) |
| C1 Dependencias instalables | 5.1, 5.5; 7.3 (Windows y CI en GitHub) |
| C2 Modelo reentrenado, `skops`, metadatos | 5.2, 5.4 |
| C3 Datos legítimos actuales (Tranco, Umbrella, `statsdga`) | 3.3, 4.2 |
| C4 Fuentes DGA (Netlab 2021, Hugging Face, corpus propio, DGArchive) | 3.4, 4.1 |
| C5 Evaluación sin solapes | 4.1, 4.2 |
| C6 `--secondary` | 2.3 |
| C7 Lista de sufijos actual | 3.2 (preparar), 5.3 (activar) |
| C8 Datos fuera de git, manifiesto y releases | 3.1, 3.5 y 5.4 (borradores locales), 7.2 (publicación) |
| C9 `checktranco()` y `loadngram()` | 2.4 |
| C10 `n_jobs` | 5.2 |
| C11 NLTK sin red al importar | 2.5, 3.1 (`--nltk`) |
| C12 `--check` emparejado | 2.1 |
| C13 CSV limpio en `-C` | 2.2 |
| Riesgo: compatibilidad con pandas 3.0 y numpy 2 | 1.6, 5.1 |
| Riesgo: desfase de características | 5.4 (prueba de paridad) |
| Riesgo: veredictos que cambian | 5.4 (verificación manual), 1.4 actualizada |
| Riesgo: tiempo de reentrenamiento | 1.6 (estimación), 5.4 (medida) |
| Riesgo: quien clona necesita un paso más | 3.1 (mensaje y README) |
| Riesgo: licencias de los datos | 3.4 |
| Riesgo: pruebas antes del cambio en `detectdga.py` | Regla general de la cabecera; cada tarea de las fases 2, 4 y 5 |
| Documentación que hay que actualizar | 2.5, 2.6, 3.1, 4.4 (por fase); 6.1–6.4 (pasada final) |
| Fuera de alcance («Lo que no se arregla ahora») | No se entrega: sigue en `docs/FUTURE.md` |
