# CLAUDE.md: acuerdo de trabajo para DGA

Instrucciones para agentes de IA y personas que contribuyan a este repositorio. Léelas antes de tocar nada.

## Qué es

DGA es un laboratorio de terminal, nacido en un máster de análisis de malware, para estudiar los algoritmos de
generación de dominios (DGA). Tiene tres partes:

- un catálogo de 50 generadores reimplementados (`lookdga.py`): ficha, generación, lista de bloqueo, sospecha
  por patrón y atribución por fuerza bruta;
- un detector Random Forest que clasifica dominios como generados o humanos (`detectdga.py`);
- un menú de estadísticas (`statsdga.py`).

Su público es quien lo descubre en GitHub para aprender o evaluarlo, no analistas en producción. Hoy
funciona en un entorno de 2021 y está en puesta a punto.

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
DGAs/wordlist/  diccionarios de generadores, sufijos públicos, top-1m de Alexa
ml-data/        listas *.dom, tranco.ng1-4, full/tiny .pkl + -scaler.pkl (367 MB en git)
yara/           35 reglas de Malpedia, hoy sin uso en el código
docs/           documentación de la puesta a punto (en español)
```

## Entorno, ejecución y pruebas

- **Python 3.9 en x86_64** con las versiones exactas de `requirements.txt`. Es el único entorno en el que el
  detector funciona hoy. En Apple Silicon solo se instala bajo Rosetta:
  ```bash
  arch -x86_64 /usr/bin/python3 -m venv venv39x
  arch -x86_64 venv39x/bin/pip install --only-binary :all: -r requirements.txt
  ```
  `venv/` ya está ignorado. Para un nombre distinto, crea el entorno fuera del repositorio.
- **Ejecuta siempre desde la raíz del repositorio:**
  - `python lookdga.py -L`
  - `python lookdga.py -m tinba -n 5 -G`
  - `python lookdga.py -B nvfowikhevmy.net`
  - `python detectdga.py --check google.com nvfowikhevmy.net`
  - `python statsdga.py`
- **Sin red:** si el corpus `brown` de NLTK ya está descargado, exporta `NLTK_DATA=<ruta>` y no se intentará
  descargar.
- **Compilación:** no hay.
- **Pruebas: no existen.** No hay `tests/`, `pytest` ni CI. Hasta que lleguen (etapa 1.1.11 de
  `docs/FUTURE.md`):
  - comprueba cada cambio ejecutando a mano los criterios de aceptación de `docs/MVP.md` que afecte;
  - di qué ejecutaste y qué resultado viste;
  - si algo no lo ejecutaste, dilo como «no verificado». Nunca lo des por bueno.
- Si añades pruebas, ponlas en `tests/` con `pytest` y documenta en `README.md` el comando exacto. Esa es la
  convención decidida para la etapa 1.1, no algo que ya exista.

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
- No subas ficheros de más de 100 MB: GitHub los rechaza, y `full.pkl` ya pesa 99,9 MB.

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
4. **Las características del modelo están copiadas en cinco sitios** (`detectdga.py` `createmaindataset`,
   `createtestdataset` ×2, `createalexadataset`, `testdomains`). Si cambias una, cámbiala en todos con el
   mismo orden de columnas.
   *Por qué:* el modelo solo ve un vector por posición. Si el orden de entrenamiento y el de predicción no
   coinciden, el detector da veredictos erróneos sin ningún aviso.
5. **Modelo, escalador y diccionario de n-gramas van juntos.** Si cambias uno, regenera los otros y vuelve a
   medir.
   *Por qué:* no hay versión ni hash que los ate. Un `full.pkl` nuevo con un `full-scaler.pkl` viejo, o un
   `tranco.ng*` distinto, rompe las predicciones en silencio.
6. **No actualices scikit-learn, pandas ni numpy sin reentrenar y volver a guardar los modelos.**
   *Por qué:* los pickles de scikit-learn 0.24.2 no cargan en scikit-learn 1.9.1 (verificado, `docs/MVP.md`
   §0).
7. **Nunca cargues pickles de origen desconocido ni subas al repositorio pickles que no hayas generado tú.**
   *Por qué:* `pickle.load` ejecuta código, y el repositorio es público y obliga a cargar sus `.pkl`
   (`docs/ARCHITECTURE.md` §7).
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
    *Por qué:* hoy solo usan la biblioteca estándar y son la parte que funciona fuera del entorno de 2021.
13. **No lances `--ngram`, `--main`, `--secondary`, `--alexa` ni `--train` sin avisar.** Sobrescriben ficheros
    de `ml-data/` y tardan mucho; suposición: horas.
    *Por qué:* `full.pkl` y `tranco.ng*` son los únicos ejemplares del modelo de 2021. Antes de regenerarlos,
    haz una copia fuera del repositorio.
14. **`lookdga.py -C` escribe datos en la salida estándar.** No añadas nada más a esa salida.
    *Por qué:* el README la redirige a `ml-data/mydgas.dom`, y las dos líneas de estado que ya imprime
    ensucian el CSV.
15. **No edites `ml-data/*.dom` ni `DGAs/wordlist/*` a mano.** Si cambias una fuente, documenta de dónde sale
    y cómo se obtuvo.
    *Por qué:* son datos de terceros (Tranco, 360 Netlab, Alexa, Mozilla) y el estudio depende de poder
    reconstruirlos.
16. **No toques `.idea/`.**
    *Por qué:* es configuración personal de PyCharm que quedó versionada por accidente
    (`docs/ARCHITECTURE.md` §11). Qué hacer con ella lo decide el usuario.
17. **Toda afirmación sobre el comportamiento, en docs, README o mensajes, debe estar verificada o marcada
    como «no verificado».**
    *Por qué:* el README original prometía cosas que el código no cumplía (`docs/ESTUDIO.md` §9), y corregir
    eso es el objetivo de la puesta a punto.
