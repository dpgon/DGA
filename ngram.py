import pandas as pd
import numpy as np
from sklearn import preprocessing


class ngrams:
    def __init__(self):
        self._ngram = [None, {}, {}, {}, {}]
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
        dfs = []
        for n in self._ngram:
            if n:
                index = []
                columns = []
                for key in n:
                    index.append(key)
                    columns.append(n[key])
                df = pd.DataFrame(columns, index=index, columns=['value'])
                x = df.values
                min_max_scaler = preprocessing.MinMaxScaler()
                x_scaled = min_max_scaler.fit_transform(x)
                df = pd.DataFrame(x_scaled, index=index, columns=['value'])
                dfs.append(df)
        self.ngram1, self.ngram2, self.ngram3, self.ngram4 = dfs

    def save(self, filename):
        self.ngram1.to_pickle(f"{filename}.ng1")
        self.ngram2.to_pickle(f"{filename}.ng2")
        self.ngram3.to_pickle(f"{filename}.ng3")
        self.ngram4.to_pickle(f"{filename}.ng4")

    def load(self, filename):
        self.ngram1 = pd.read_pickle(f"{filename}.ng1")
        self.ngram2 = pd.read_pickle(f"{filename}.ng2")
        self.ngram3 = pd.read_pickle(f"{filename}.ng3")
        self.ngram4 = pd.read_pickle(f"{filename}.ng4")

    def _checkdom(self, domain, l):
        data = []
        for c in range(len(domain) - l + 1):
            ng = domain[c:c + l]
            if ng in eval(f"self.ngram{l}['value']"):
                data.append(eval(f"self.ngram{l}['value']['{ng}']"))
            else:
                data.append(0)
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
