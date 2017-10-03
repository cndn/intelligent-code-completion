import os
import torch
import sys
sys.path.append('../tokenizer')
import tokenizer
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
    def __init__(self, path):
        self.dictionary = Dictionary()
        self.train = self.tokenize(os.path.join(path, '../dataset/train.txt'))
        self.valid = self.tokenize(os.path.join(path, '../dataset/valid.txt'))
        self.test = self.tokenize(os.path.join(path, '../dataset/test.txt'))

    def tokenize(self, path):
        """Tokenizes a text file."""
        assert os.path.exists(path)
        tokens = 0
        # Find code path and create dictionary
        with open(path, 'r') as f:
            for line in f:
                filename = line.strip()
                code_path = '../raw_data/' + filename
                assert os.path.exists(code_path)
                try:
                    with open(code_path, 'r') as code_f:
                        code = code_f.read()
                        words = tokenizer.tokenize_code_without_id(code) + ['<eos>']
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
                code_path = '../raw_data/' + filename
                assert os.path.exists(code_path)
                try:
                    with open(code_path, 'r') as code_f:
                        code = code_f.read()
                        words = tokenizer.tokenize_code_without_id(code) + ['<eos>']
                        for word in words:
                            ids[token] = self.dictionary.word2idx[word]
                            token += 1
                except:
                    pass
        return ids

if __name__ == '__main__':
    corpus = Corpus('')
    print corpus.train.size()
