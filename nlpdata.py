import sys


def requirebrown():
    '''
    Check that the NLTK brown corpus (used to count syllables) is installed, without downloading it.
    If it is missing, exit with the command that installs it.
    '''
    import nltk
    try:
        nltk.data.find('corpora/brown')
    except LookupError:
        print("The NLTK brown corpus is not installed. Install it once with:\n"
              "  python -m nltk.downloader -d <directory> brown\n"
              "and set NLTK_DATA=<directory> (or use ~/nltk_data as the directory).", file=sys.stderr)
        sys.exit(1)
