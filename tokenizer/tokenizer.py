
# coding: utf-8

from parso.python.tokenize import tokenize

index = 0
def tokenize_code(code):
    return [(token.type, token.string if token.type != 3 else '') for token in tokenize(code, (2, 7))]

def generate_pseudo_words(w, pseudo_words,p_dict):
    global index
    if w in p_dict:
        return 'pvar_'+str(p_dict[w])
    index = (index + 1) % 10
    p_dict[w] = index
    return 'pvar_'+str(pseudo_words[index])

def tokenize_code_no_rare(code, **kwargs):
    res = tokenize_code(code)
    vocab, pseudo_words, p_dict = kwargs.get('vocab',set()), kwargs['pseudo_words'], kwargs['p_dict']
    return [a if str(a) in vocab else (a[0],generate_pseudo_words(a[1],pseudo_words,p_dict)) for a in res]

def naive_tokenizer(string):
    return [val if val in wordFreq else 'unk' for val in re.findall('\\w+', string)]

def tokenize_wrapper(string, **kwargs):
    return tokenize_code_no_rare(string, **kwargs)

if __name__ == '__main__':
    f = open('../dataset/split.py','r')
    print tokenize_wrapper(f.read())
