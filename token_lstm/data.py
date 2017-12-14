import os
import torch
import sys
sys.path.append('../tokenizer')
import tokenizer
import operator
import random

RAW_DATA_PATH = '../../intelligent-code-completion/raw_data/'
REMOVE_THRESHOLD = 10

class Dictionary(object):
    def __init__(self):
        self.word2idx = {}
        self.idx2word = []

    def add_word(self, word):
        if word not in self.word2idx:
            self.idx2word.append(word)
            self.word2idx[word] = len(self.idx2word) - 1
        return self.word2idx[word]

    def __len__(self):
        return len(self.idx2word)


class Corpus(object):
    def __init__(self, path, word_count):
        # print word_count
        self.vocab = set()
        with open(word_count, 'r') as f:
            for line in f.xreadlines():
                try:
                    w,c = line.strip().split('\t')
                    if int(c) > REMOVE_THRESHOLD:
                        self.vocab.add(w)
                except:
                    pass
        self.dictionary = Dictionary()
        self.tic_marks = []
        self.train = self.tokenize(os.path.join(path, '../dataset/tf_train.txt'))
        self.valid = self.train
        # self.valid = self.tokenize(os.path.join(path, '../dataset/tf_train.txt'))
        # self.test = self.tokenize(os.path.join(path, '../dataset/tiny_test.txt'))
        
        

    def tokenize(self, path):
        """Tokenizes a text file."""
        assert os.path.exists(path)
        tokens = 0
        maxLen = 0
        # Find code path and create dictionary
        with open(path, 'r') as f:
            for i, line in enumerate(f):
                filename = line.strip()
                code_path = RAW_DATA_PATH + filename
                assert os.path.exists(code_path)
                try:
                    with open(code_path, 'r') as code_f:
                        code = code_f.read()
                        if len(code) > 100000:
                            continue
                        kwargs = {'vocab':self.vocab}
                        words = tokenizer.tokenize_wrapper(code, **kwargs)
                        tokens += len(words)
                        for word in words:
                            self.dictionary.add_word(word)
                except:
                    pass
        # Tokenize file content
        with open(path, 'r') as f:
            ids = torch.LongTensor(tokens)
            token = 0
            for line in f:
                filename = line.strip()
                code_path = RAW_DATA_PATH + filename
                assert os.path.exists(code_path)
                try:
                    with open(code_path, 'r') as code_f:
                        code = code_f.read()
                        if len(code) > 100000:
                            continue
                        kwargs = {'vocab':self.vocab}
                        words = tokenizer.tokenize_wrapper(code, **kwargs)
                        for word in words:
                            ids[token] = self.dictionary.word2idx[word]
                            token += 1
                        self.tic_marks.append(len(words))
                except Exception as e:
                    #raise e
                    pass
        return ids

if __name__ == '__main__':
    corpus = Corpus('','../statistics/count_without_type.txt')
    print corpus.train
