import operator
import os
import sys
sys.path.append('../tokenizer')
import tokenizer
def word_count(train, out):
    d = {}
    output = open(out,'w')
    with open(train,'r') as f:
        for i, line in enumerate(f):
            if i % 1000 == 0:
                print i
            filename = line.strip()
            code_path = '../raw_data/' + filename
            assert os.path.exists(code_path)
            try:
                with open(code_path, 'r') as code_f:
                    code = code_f.read()
                    words = tokenizer.tokenize_wrapper(code) + ['<eos>']
                    for word in words:
                        d[word] = d.get(word, 0) + 1
            except:
                pass
    for item in sorted(d.items(), key=operator.itemgetter(1), reverse=True):
        if len(item[0]) > 10:
            continue
        output.write(str(item[0]) + '\t' + str(item[1]) + '\n')

if __name__ == '__main__':
    word_count('../dataset/tf_train.txt', 'tf_count_with_type.txt')
                

