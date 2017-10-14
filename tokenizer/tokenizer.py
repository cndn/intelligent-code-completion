
# coding: utf-8

from parso.python.tokenize import tokenize

def tokenize_code(code):
    return [(token.type, token.string if token.type != 3 else '') for token in tokenize(code, (2, 7))]

def tokenize_code_no_rare(code, vocab=set()):
    res = tokenize_code(code)
    if len(vocab) == 0:
        return res
    return [a for a in res if str(a) in vocab]

def naive_tokenizer(string):
    return [val if val in wordFreq else 'unk' for val in re.findall('\\w+', string)]

def tokenize_wrapper(string, vocab = set()):
    return tokenize_code_no_rare(string, vocab)

if __name__ == '__main__':
    f = open('../dataset/split.py','r')
    print tokenize_code(f.read())
