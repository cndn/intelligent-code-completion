
# coding: utf-8

from parso.python.tokenize import tokenize

def tokenize_code(code):
    return [(token.type, token.string if token.type != 3 else '') for token in tokenize(code, (2, 7))]

def tokenize_code_no_rare(string, concat_symbol=None):
    return [val if val in wordFreq or val in specials else 'unk' for (id, val) in tokenize_code(string)]

def naive_tokenizer(string):
    return [val if val in wordFreq else 'unk' for val in re.findall('\\w+', string)]

def tokenize_wrapper(string):
    return naive_tokenizer(string)

if __name__ == '__main__':
    f = open('../dataset/split.py','r')
    print tokenize_code_(f.read())
