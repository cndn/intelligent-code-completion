###############################################################################
#
###############################################################################

import argparse

import torch
from torch.autograd import Variable
import random
import sys
import data
sys.path.append('../tokenizer')
import tokenizer

parser = argparse.ArgumentParser(description='PyTorch PTB Language Model')

# Model parameters.
parser.add_argument('--data', type=str, default='',
                    help='location of the data corpus')
parser.add_argument('--checkpoint', type=str, default='./model_cpu.pt',
                    help='model checkpoint to use')
parser.add_argument('--outf', type=str, default='generated_code.py',
                    help='output file for generated text')
parser.add_argument('--words', type=int, default='1000',
                    help='number of words to generate')
parser.add_argument('--seed', type=int, default=1032,
                    help='random seed')
parser.add_argument('--cuda', action='store_true',
                    help='use CUDA')
parser.add_argument('--temperature', type=float, default=1.0,
                    help='temperature - higher will increase diversity')
parser.add_argument('--log-interval', type=int, default=100,
                    help='reporting interval')
args = parser.parse_args()

d = {2:'NUM', 3:'STR', 4:'\n', 5:'INDENT', 6:'DEDENT', 7:'(', 8:')', 9:'[', 10:']', 11:':', 12:',', 13:';', 
             14:'+', 15:'-', 16:'*', 17:'/', 18:'|', 19:'&', 20:'<', 21:'>', 22:'=', 23:'.', 24:'%', 26:'{',
             27:'}',28:'==',29:'!=',30:'<=',31:'>=',36:'**',50:'@'}
word_symbol_map = {}
symbol_index_map = {}
for key in d:
    word_symbol_map['TYPE_' + str(key)] = d[key]
    symbol_index_map[d[key]] = key

class Test(object):
    def __init__(self):
        torch.manual_seed(args.seed)
        if torch.cuda.is_available():
            if not args.cuda:
                print("WARNING: You have a CUDA device, so you should probably run with --cuda")
            else:
                torch.cuda.manual_seed(args.seed)
        if args.temperature < 1e-3:
            parser.error("--temperature has to be greater or equal 1e-3")
        self.indent = 0
        self.model = None
        self.corpus = None
        self.indent = 0
        self.prev = None

    def load(self, model_filename = args.checkpoint, wc_filename='../statistics/tf_count_without_type.txt'):
        with open(model_filename, 'rb') as f:
            self.model = torch.load(f)
            self.model.eval()
            if args.cuda:
                self.model.cuda()
            else:
                self.model.cpu()
            self.corpus = data.Corpus(args.data,wc_filename)
        print 'loaded!'

    def decode(self,s):
        symbol = word_symbol_map.get(s, s)
        if symbol == 'INDENT':
            self.indent += 1
            return ''
        elif symbol == 'DEDENT':
            self.indent = max([self.indent - 1,0])
            return ''
        elif self.prev == '\n':
            self.prev = symbol
            return '    ' * self.indent + symbol
        prefix = '' if symbol in symbol_index_map or self.prev in symbol_index_map else ' '
        self.prev = symbol
        return prefix + symbol

    def predict_next(self, code,suggestion=10):
        ntokens = len(self.corpus.dictionary)
        hidden = self.model.init_hidden(1)
        input = Variable(torch.rand(1, 1).mul(ntokens).long(), volatile=True)
        if args.cuda:
            input.data = input.data.cuda()
        kwargs = {'vocab':self.corpus.vocab}
        tokens = tokenizer.tokenize_wrapper(code,kwargs['vocab'], inference=True)
        for token in tokens:
            word_idx = self.corpus.dictionary.word2idx.get(token, 0)
            input.data.fill_(word_idx)
            output, hidden = self.model(input, hidden)
        word_weights = output.squeeze().data.div(args.temperature).exp().cpu()
        word_idx = torch.topk(word_weights, suggestion)[1]
        res = [self.decode(self.corpus.dictionary.idx2word[word_idx[i]]) for i in range(suggestion)]
        return res

    def generate(self, code, step = 100, output_file='generated_code.py'):
        ntokens = len(self.corpus.dictionary)
        hidden = self.model.init_hidden(1)
        input = Variable(torch.rand(1, 1).mul(ntokens).long(), volatile=True)
        output_str = []
        if args.cuda:
            input.data = input.data.cuda()
        kwargs = {'vocab':self.corpus.vocab}
        tokens = tokenizer.tokenize_wrapper(code,kwargs['vocab'], inference=True)
        for token in tokens:
            word_idx = self.corpus.dictionary.word2idx.get(token, 0)
            input.data.fill_(word_idx)
            output, hidden = self.model(input, hidden)
        for i in range(step):
            word_weights = output.squeeze().data.div(args.temperature).exp().cpu()
            word_idx = torch.multinomial(word_weights, 1)[0]
            input.data.fill_(word_idx)
            candidate = self.decode(self.corpus.dictionary.idx2word[word_idx])
            if 'TYPE_0' in candidate:
                # candidate = '\n'
                # self.indent = 0
                # self.prev = None
                break
            output_str.append(candidate)
            output, hidden = self.model(input, hidden)
        with open(output_file, 'w') as f:
            f.write(code + ''.join(output_str))
            
    def statistics(self, suggestion=10):
        unk_num = 0
        test_num = 0
        total_count = 0
        correct = 0
        print('LSTM model')
        test_set = []
        with open('../dataset/tf_valid.txt', 'r') as reader:
            for line in reader:
                test_set.append(line.strip())
        for filename in test_set:
            with open(filename) as reader:
                code = reader.read()
                #code = "for i in range"
            ntokens = len(self.corpus.dictionary)
            hidden = self.model.init_hidden(1)
            input = Variable(torch.rand(1, 1).mul(ntokens).long(), volatile=True)
            if args.cuda:
                input.data = input.data.cuda()
            kwargs = {'vocab':self.corpus.vocab}
            try:
                tokens = tokenizer.tokenize_wrapper(code,kwargs['vocab'], inference=True)
            except:
                continue
            for (token, pred) in zip(tokens, tokens[1:]):
                word_idx = self.corpus.dictionary.word2idx.get(token, 0)
                input.data.fill_(word_idx)
                output, hidden = self.model(input, hidden)
                word_weights = output.squeeze().data.div(args.temperature).exp().cpu()
                word_idx = torch.topk(word_weights, suggestion)[1]
                res = [self.decode(self.corpus.dictionary.idx2word[word_idx[i]]).lstrip() for i in range(suggestion)]
                if 'TYPE_' in pred:
                    if pred not in word_symbol_map:
                        continue
                    pred = word_symbol_map[pred]
                total_count += 1
                if pred == 'unk':
                    unk_num += 1
                if res[0] == 'unk':
                    continue
                if pred in res:
                    correct += 1
            test_num += 1
            print test_num

        print('Top{0}-Accuracy = {1}').format(suggestion, float(correct) / total_count)
        print('UNK_NUM: {0}/{1}').format(unk_num ,total_count)

        
if __name__ == '__main__':
    f = open('./generate_start.py','r')
    test = Test()
    test.load('model_cpu.pt')
    #test.generate(f.read(), 2000)
    #print test.predict_next('for i in')
    test.statistics(1)
