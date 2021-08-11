from datetime import datetime


class DGA:
    shortname = "pizd"
    yara = None
    name = "Pizd malware"
    ref = ["https://blog.avast.com/2013/06/18/your-facebook-connection-is-now-secured/"]
    desc = "PIZD is a malware family found by Crowdstrike, has over 1000 variants. Each one of them has a different target email address embedded in it, so probably each one of them is created for specific campaign."
    samples = 0
    lcg = None
    use_date = 1    # Changes every second
    use_seed = None
    configs = [None]
    variation = "Different domains and the tld is .net. The domains is one word from a list with 384 words, using only the first 128 posibilities, plus another word from the list (256 posibilities). The first word could start with a-e letters."
    regex = "[a-e]{1}[a-ik-pr-z]{9,20}"
    ends = ['.net']

    def __init__(self, date=None, seed=None):
        self.date = date
        self.date -= datetime.utcfromtimestamp(0)
        self.date = int(self.date.total_seconds() * 1000)
        self.wordlist = ['above', 'action', 'advance', 'afraid', 'against', 'airplane', 'almost', 'alone', 'already',
                    'although', 'always', 'amount', 'anger', 'angry', 'animal', 'another', 'answer', 'appear',
                    'apple', 'around', 'arrive', 'article', 'attempt', 'banker', 'basket', 'battle', 'beauty',
                    'became', 'because', 'become', 'before', 'begin', 'behind', 'being', 'believe', 'belong',
                    'beside', 'better', 'between', 'beyond', 'bicycle', 'board', 'borrow', 'bottle', 'bottom',
                    'branch', 'bread', 'bridge', 'bright', 'bring', 'broad', 'broken', 'brought', 'brown', 'building',
                    'built', 'business', 'butter', 'captain', 'carry', 'catch', 'caught', 'century', 'chair', 'chance',
                    'character', 'charge', 'chief', 'childhood', 'children', 'choose', 'cigarette', 'circle', 'class',
                    'clean', 'clear', 'close', 'clothes', 'college', 'company', 'complete', 'condition', 'consider',
                    'contain', 'continue', 'control', 'corner', 'country', 'course', 'cover', 'crowd', 'daughter',
                    'decide', 'degree', 'delight', 'demand', 'desire', 'destroy', 'device', 'difference', 'different',
                    'difficult', 'dinner', 'direct', 'discover', 'distance', 'distant', 'divide', 'doctor', 'dollar',
                    'double', 'doubt', 'dress', 'dried', 'during', 'early', 'eearly', 'effort', 'either', 'electric',
                    'electricity', 'english', 'enough', 'enter', 'escape', 'evening', 'every', 'except', 'expect',
                    'experience', 'explain', 'family', 'famous', 'fancy', 'father', 'fellow', 'fence', 'fifteen',
                    'fight', 'figure', 'finger', 'finish', 'flier', 'flower', 'follow', 'foreign', 'forest', 'forever',
                    'forget', 'fortieth', 'forward', 'found', 'fresh', 'friend', 'further', 'future', 'garden',
                    'gather', 'general', 'gentle', 'gentleman', 'glass', 'glossary', 'goodbye', 'govern', 'guard',
                    'happen', 'health', 'heard', 'heart', 'heaven', 'heavy', 'history', 'honor', 'however', 'hunger',
                    'husband', 'include', 'increase', 'indeed', 'industry', 'inside', 'instead', 'journey', 'kitchen',
                    'known', 'labor', 'ladder', 'language', 'large', 'laugh', 'laughter', 'leader', 'leave', 'length',
                    'letter', 'likely', 'listen', 'little', 'machine', 'manner', 'market', 'master', 'material',
                    'matter', 'mayor', 'measure', 'meeting', 'member', 'method', 'middle', 'might', 'million',
                    'minute', 'mister', 'modern', 'morning', 'mother', 'mountain', 'movement', 'nation', 'nature',
                    'nearly', 'necessary', 'needle', 'neighbor', 'neither', 'niece', 'night', 'north', 'nothing',
                    'notice', 'number', 'object', 'oclock', 'office', 'often', 'opinion', 'order', 'orderly',
                    'outside', 'paint', 'partial', 'party', 'people', 'perfect', 'perhaps', 'period', 'person',
                    'picture', 'pleasant', 'please', 'pleasure', 'position', 'possible', 'power', 'prepare', 'present',
                    'president', 'pretty', 'probable', 'probably', 'problem', 'produce', 'promise', 'proud', 'public',
                    'quarter', 'question', 'quiet', 'rather', 'ready', 'realize', 'reason', 'receive', 'record',
                    'remember', 'report', 'require', 'result', 'return', 'ridden', 'right', 'river', 'round', 'safety',
                    'school', 'season', 'separate', 'service', 'settle', 'severa', 'several', 'shake', 'share',
                    'shore', 'short', 'should', 'shoulder', 'shout', 'silver', 'simple', 'single', 'sister', 'smell',
                    'smoke', 'soldier', 'space', 'speak', 'special', 'spent', 'spread', 'spring', 'square', 'station',
                    'still', 'store', 'storm', 'straight', 'strange', 'stranger', 'stream', 'street', 'strength',
                    'strike', 'strong', 'student', 'subject', 'succeed', 'success', 'sudden', 'suffer', 'summer',
                    'supply', 'suppose', 'surprise', 'sweet', 'system', 'therefore', 'thick', 'think', 'third',
                    'those', 'though', 'thought', 'through', 'thrown', 'together', 'toward', 'trade', 'train',
                    'training', 'travel', 'trouble', 'trust', 'twelve', 'twenty', 'understand', 'understood', 'until',
                    'valley', 'value', 'various', 'wagon', 'water', 'weather', 'welcome', 'wheat', 'whether', 'while',
                    'white', 'whose', 'window', 'winter', 'within', 'without', 'woman', 'women', 'wonder', 'worth',
                    'would', 'write', 'written', 'yellow']
        self.domain = None
        self.nr = 0

    def _dga(self):
        inv_key = [0, 5, 10, 14, 9, 3, 11, 7, 2, 13, 4, 8, 1, 12, 6]
        bin_temp = bin(self.date + self.nr)[-15::1]

        nib = [0] * len(bin_temp)
        for x in range(0, 14):
            nib[x] = bin_temp[inv_key[x]]
        res = [''.join([str(char) for char in nib[:7]]), ''.join([str(char) for char in nib[7:]])]
        res = [self.wordlist[int(res[0], 2)], self.wordlist[int(res[1], 2) + 128], ".net"]
        self.domain = ''.join([str(wds) for wds in res])
        self.nr += 1

    def get_domain(self):
        self._dga()
        return self.domain
