tokenizer_path = '../tokenizer'

import kenlm
import pickle
import sys
import os
import heapq
import random
sys.path.append(tokenizer_path)
from tokenizer import tokenize_code

class Ngram(object):
    LM = 'code_corpus.arpa'
    VOCABULARY = 'vocabulary.pickle'
    COMMON = 'common_words.pickle'
    TESTPATH = '../dataset/test.txt'
    RAWDATA = '../raw_data'

    def __init__(self):
        self.model = kenlm.Model(Ngram.LM)
        with open(Ngram.VOCABULARY, 'rb') as handle:
            self.voc = pickle.load(handle)
            self.id2word = [()] * (len(self.voc) + 1)
            for (k, v) in self.voc.items():
                self.id2word[v] = k
        with open(Ngram.COMMON, 'rb') as handle:
            self.high_freq = pickle.load(handle)
            self.high_freq = map(lambda x: self.voc[x], self.high_freq)

        self.test_set = []
        with open(Ngram.TESTPATH) as reader:
            for line in reader:
                self.test_set.append(line.strip())

    def next_word(self, context):
        # return the top 10 word according to context
        tokens = tokenize_code(context)[:-1]
        while len(tokens) > 0 and tokens[-1] == (6, ''):
            tokens = tokens[:-1]
        # print tokens
        return self.next_word_by_tokens(tokens)

    def next_word_by_tokens(self, tokens):
        candidate = set(self.high_freq)
        state = kenlm.State()
        state2 = kenlm.State()
        tids = map(lambda x: self.voc[x] if x in self.voc else 0, tokens[-5:])
        candidate |= set(map(lambda x: self.voc[x] if x in self.voc else 0, tokens))

        if len(tids) < 5:
            self.model.BeginSentenceWrite(state)
        else:
            self.model.NullContextWrite(state)
        # state query
        for tid in tids:
            self.model.BaseScore(state, str(tid), state2)
            state, state2 = state2, state
        # find max candidate
        ranking = []
        for tid in candidate:
            p = self.model.BaseScore(state, str(tid), state2)
            heapq.heappush(ranking, (p, tid))

        return map(lambda (max_p, max_id): '<unk>' if max_id == 0 else self.id2word[max_id][1],
                   heapq.nlargest(10, ranking))

    def statistics(self):
        test_num = 0
        total_count = 0
        correct = 0
        print('{0}-gram model'.format(self.model.order))
        for filename in random.sample(self.test_set, 10):
            with open(os.path.join(Ngram.RAWDATA, filename)) as reader:
                code = reader.read()
            tokens = tokenize_code(code)
            for i in range(1, len(tokens) - 1):
                prediction = self.next_word_by_tokens(tokens[:i])
                total_count += 1
                if tokens[i][1] in prediction:
                    correct += 1
            test_num += 1
            #if test_num % 500 == 0:
            print test_num

        print('Top10-Accuracy = {0}').format(float(correct) / total_count)



#if __name__ == '__main__':
#    ngram = Ngram()
#    ngram.statistics()