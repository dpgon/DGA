# DGA
Study of the different algorithms and techniques for generating DGA and discrimination against non-DGA domains

Download Tranco wordlist from https://tranco-list.eu/list/9Q72/full
```
$ sed -n '1,1500000p' tranco.csv | cut -d ',' -f 2 > tranco-main.dom
$ sed -n '1500001,2000000p' tranco.csv | cut -d ',' -f 2 > tranco-test2.dom
$ sed -n '2000001,20000000p' tranco.csv | cut -d ',' -f 2 > tranco-ngram.dom
```
Download DGA domains for main dataset from https://data.netlab.360.com/feeds/dga/dga.txt

To create DGAs to second test dataset:
```
$ python3 lookdga.py -d 2019-12-31 -n 3000 -C > ml-data/mydgas.dom
```

