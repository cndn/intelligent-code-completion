import os
import torch
import sys
sys.path.append('../tokenizer')
import tokenizer
import operator
import random

RAW_DATA_PATH = '../../intelligent-code-completion/raw_data/'

class Dictionary(object):
    def __init__(self):
        self.word2idx = {}
        self.idx2word = []

    def add_word(self, word):
        if word not in self.word2idx:
            self.idx2word.append(word)
            self.word2idx[word] = len(self.idx2word) - 1
        return self.word2idx[word]

    def get_idx(self, word):
        if word not in self.word2idx:
            raise KeyError("Out of vocabulary")
        return self.word2idx[word]

    def get_word(self, idx):
        if idx < 0 or idx >= len(self.idx2word):
            raise KeyError("Out of range")
        return self.idx2word[idx]

    def __len__(self):
        return len(self.idx2word)


class Corpus(object):
    def __init__(self, path, word_count):
        self.pseudo_count = 10
        # print word_count
        self.vocab = set()
        with open(word_count, 'r') as f:
            for line in f.xreadlines():
                try:
                    w,c = line.strip().split('\t')
                    if int(c) > 10:
                        self.vocab.add(w)
                except:
                    pass
        
        self.dict = Dictionary()
        self.train = self.tokenize(os.path.join(path, '../dataset/tf_train.txt'))
        self.valid = self.tokenize(os.path.join(path, '../dataset/tf_train.txt'))
        self.test = self.tokenize(os.path.join(path, '../dataset/tiny_test.txt'))
        

    def tokenize(self, path):
        """Tokenizes a text file."""
        assert os.path.exists(path)
        # Tokenize file content
        ret = []
        current_sts = []
        with open(path, 'r') as f:
            for line in f:
                filename = line.strip()
                code_path = RAW_DATA_PATH + filename
                assert os.path.exists(code_path)
                try:
                    with open(code_path, 'r') as code_f:
                        code = code_f.read()
                        kwargs = {'vocab':self.vocab}
                        words = tokenizer.tokenize_wrapper(code, **kwargs) + ['<eos>']
                        for word in words:
                            if not word in self.dict.word2idx:
                                self.dict.add_word(word)
                            current_sts.append(self.dict.get_idx(word))
                            if len(current_sts) >= 80:
                                ret.append(current_sts)
                                current_sts = []

                except Exception as e:
                    #raise e
                    pass
        return ret

    # def tokenize(self, path):
    #     ret = []
    #     current_sts = []
    #     with open(path, 'r') as f:
    #         for line in f.readlines():
    #             for token in line.split() + ['</s>']:
    #                 if not token in self.dict.word2idx:
    #                     self.dict.add_word(token)
    #                 current_sts.append(self.dict.get_idx(token))
    #                 if len(current_sts) >= 80:
    #                     ret.append(current_sts)
    #                     current_sts = []
    #     return ret

if __name__ == '__main__':
    corpus = Corpus('','../statistics/tf_count_with_type.txt')
    print corpus.dictionary.idx2word
