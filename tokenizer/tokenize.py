
# coding: utf-8

# In[1]:

from tokenize import *
from token import tok_name as py_token_name
from StringIO import StringIO


# In[2]:

token_id = {token_name: token_id for token_id, token_name in enumerate(py_token_name.values())}
token_name = {token_id[token_name]: token_name for token_name in token_id}


# In[3]:

def add_token(name):
    tid = len(token_id)
    token_id[name] = tid
    token_name[tid] = name
    return tid


# In[4]:

TOKEN_NAME = py_token_name[NAME]
TOKEN_SUBNAME = 'SUBNAME'
TOKEN_NAMECON = 'NAMECON'
SUBNAME = add_token(TOKEN_SUBNAME)
NAMECON = add_token(TOKEN_NAMECON)


# In[5]:

def tokenize_camel_case(string):
    words = []
    from_char_position = 0
    for current_char_position, (current_char, prev_char) in enumerate(zip(string,'a' + string)):
        if prev_char.isupper() and current_char.islower() and from_char_position < current_char_position - 1:
            words.append(string[from_char_position:current_char_position - 1])
            from_char_position = current_char_position - 1
    words.append(string[from_char_position:])
    return words


# In[6]:

def tokenize_underscore(string):
    words = []
    for word in string.split('_'):
        if words:
            words.append('_')
        if word:
            words.append(word)
    return words


# In[7]:

def tokenize_name(string, concat_symbol=None):
    words = []
    con = [] if concat_symbol is None else [(NAMECON, concat_symbol)]
    for sub_name in tokenize_camel_case(string):
        for word in tokenize_underscore(sub_name):
            words += [(SUBNAME, word)] + con
    if words and words[-1] == concat_symbol:
        return words[:-1]
    return words


# In[8]:

def tokenize_code(string, concat_symbol=None):
    tokens = []
    string = string.strip().decode('utf-8').encode('ascii', 'replace').decode('string_escape')
    for toknum, tokval, _, _, _  in generate_tokens(StringIO(string).readline):
        tokname = py_token_name[toknum]
        if tokname == TOKEN_NAME:
            tokens.extend(tokenize_name(tokval, concat_symbol=concat_symbol))
        else:
            tokens.append((token_id[tokname], tokval))
    return tokens


# In[ ]:



