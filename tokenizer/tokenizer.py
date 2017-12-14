
# coding: utf-8
from parso.python.tokenize import tokenize
from parso.python.tokenize import PythonToken
from parso import load_grammar

def tokenize_without_endmarker(code):
    safeword = 'ZZZ_USER_WANTS_TO_COMPLETE_HERE'
    grammar = load_grammar()
    tokens = grammar._tokenize(code + safeword)
    for token_ in tokens:
        if token_.string == safeword:
            return
        elif token_.string.endswith(safeword):
            yield PythonToken(token_.type, token_.string[:-len(safeword)], token_.start_pos, token_.prefix)
            return
        else:
            yield token_


def token_filter(token_type, token_string):
    if token_type == 3:
        return ''
    elif token_type != 1:
        return 'TYPE_' + str(token_type)
    else:
        return token_string

def tokenize_code(code, inference=False):
    if inference:
        return [token_filter(token.type, token.string) for token in tokenize_without_endmarker(code)]
    return [token_filter(token.type, token.string) for token in tokenize(code, (2, 7))]

def tokenize_code_no_rare(code, vocab=set(), debug=False, inference=False):
    res = tokenize_code(code, inference)

    if debug:
        print vocab
        print res
    if len(vocab) == 0:
        return res
    return [a if a in vocab else 'unk' for a in res]

def naive_tokenizer(string):
    return [val if val in wordFreq else 'unk' for val in re.findall('\\w+', string)]

def tokenize_wrapper(string, vocab = set(), debug=False, inference=False):
    return tokenize_code_no_rare(string, vocab, debug, inference)

if __name__ == '__main__':
    f = open('../dataset/split.py','r')
    print tokenize_code(f.read())