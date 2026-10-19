import csv
import numpy as np
from sklearn import preprocessing


class ngrams:
    def __init__(self):
        self._ngram = [None, {}, {}, {}, {}]
        # Scaled frequency of every n-gram, one dict per order: {ngram: value between 0 and 1}
        self.ngram1 = None
        self.ngram2 = None
        self.ngram3 = None
        self.ngram4 = None

    def ngrams(self, domain):
        for l in range(1, 5):
            for c in range(len(domain) - l + 1):
                ng = domain[c:c + l]
                if ng in self._ngram[l]:
                    self._ngram[l][ng] += 1
                else:
                    self._ngram[l][ng] = 1

    def train(self, domains):
        for domain in domains:
            items = domain.split('.')
            if len(items[0]) > 3:
                sld = items[0]
                self.ngrams(sld)
        dicts = []
        for n in self._ngram:
            if n:
                index = list(n)
                x = np.array([[n[key]] for key in index])
                min_max_scaler = preprocessing.MinMaxScaler()
                x_scaled = min_max_scaler.fit_transform(x)
                dicts.append({key: float(value) for key, value in zip(index, x_scaled[:, 0])})
        self.ngram1, self.ngram2, self.ngram3, self.ngram4 = dicts

    def save(self, filename):
        '''
        Save the dictionary as text, one CSV file per order (C2: no pickles)
        :param filename: name without extension; the files are filename.ng1.csv ... filename.ng4.csv
        '''
        for l in range(1, 5):
            with open(f"{filename}.ng{l}.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ngram", "value"])
                # repr() of a float keeps every digit, so loading gives back the same value
                writer.writerows((ng, repr(value)) for ng, value in getattr(self, f"ngram{l}").items())

    def load(self, filename):
        '''
        Load a dictionary saved by save()
        :param filename: name without extension of the filename.ng1.csv ... filename.ng4.csv files
        '''
        for l in range(1, 5):
            with open(f"{filename}.ng{l}.csv", newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                if next(reader, None) != ["ngram", "value"]:
                    raise ValueError(f"{filename}.ng{l}.csv: the header must be ngram,value")
                setattr(self, f"ngram{l}", {ng: float(value) for ng, value in reader})

    def _checkdom(self, domain, l):
        data = []
        for c in range(len(domain) - l + 1):
            ng = domain[c:c + l]
            data.append(getattr(self, f"ngram{l}").get(ng, 0))
        return np.mean(data), np.median(data), np.std(data)

    def getmean(self, domain, l):
        items = domain.split('.')
        if len(items[0]) > 3:
            sld = items[0]
            mean, median, std = self._checkdom(sld, l)
            return mean
        else:
            return None

    def getmedian(self, domain, l):
        items = domain.split('.')
        if len(items[0]) > 3:
            sld = items[0]
            mean, median, std = self._checkdom(sld, l)
            return median
        else:
            return None

    def getstdn(self, domain, l):
        items = domain.split('.')
        if len(items[0]) > 3:
            sld = items[0]
            mean, median, std = self._checkdom(sld, l)
            return std
        else:
            return None

    def getall(self, domain, l):
        items = domain.split('.')
        if len(items[0]) > 3:
            sld = items[0]
            mean, median, std = self._checkdom(sld, l)
            return mean, median, std
        else:
            return None, None, None

    def getallngrams(self, domain):
        output = []
        for l in range(1, 5):
            items = domain.split('.')
            if len(items[0]) > 3:
                sld = items[0]
                mean, median, std = self._checkdom(sld, l)
                output.append([mean, median, std])
            else:
                return None
        return output
