src_path = '../'
tokenizer_path = '../tokenizer'
dataset_path = '../dataset'
rawdata_path = '../raw_data'

import sys
import os
import pickle
from collections import defaultdict
sys.path.append(tokenizer_path)
from tokenizer import tokenize_code

def main():
    # vocabulary: map tuple(type,token) to id
    voc = {}
    # vocabulary: map tuple(type,token) to count
    voc_count = defaultdict(int)
    # assign id
    count = 1
    # train set
    train_set = []
    # tokens corpus
    corpus = []
    # id corpus
    processed_corpus = []
    # frequent word list
    high_freq = []

    # get train set
    with open(os.path.join(dataset_path, 'train.txt')) as reader:
        for line in reader:
            train_set.append(line.strip())

    print "Generate vocabulary"
    num = 0
    for filename in train_set:
        with open(os.path.join(rawdata_path, filename)) as reader:
            code = reader.read()
        num += 1
        if num % 500 == 0:
            print num
        try:
            tokens = tokenize_code(code)
        except:
            continue
        for token in tokens:
            voc_count[token] += 1
        corpus.append(tokens)

    for (k, v) in voc_count.items():
        if v > 50:
            high_freq.append(k)
        if v > 2 and k not in voc:
            voc[k] = count
            count += 1

    print 'Preprocess corpus'
    for doc in corpus:
        document = []
        for token in doc:
            if token in voc:
                document.append(voc[token])
            else:
                document.append(0)
        processed_corpus.append(' '.join(map(lambda x: str(x), document)))

    print 'Dump to disk'
    with open('code_corpus.txt', 'w') as writer:
        writer.write('\n'.join(processed_corpus))

    with open('vocabulary.pickle', 'wb') as handle:
        pickle.dump(voc, handle, protocol=pickle.HIGHEST_PROTOCOL)

    with open('common_words.pickle', 'wb') as handle:
        pickle.dump(high_freq, handle, protocol=pickle.HIGHEST_PROTOCOL)

if __name__ == '__main__':
    main()



