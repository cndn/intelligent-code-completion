###############################################################################
#
###############################################################################

import argparse

import torch
from torch.autograd import Variable

import sys
import data
sys.path.append('../tokenizer')
import tokenizer

parser = argparse.ArgumentParser(description='PyTorch PTB Language Model')

# Model parameters.
parser.add_argument('--data', type=str, default='',
                    help='location of the data corpus')
parser.add_argument('--checkpoint', type=str, default='./model.pt',
                    help='model checkpoint to use')
parser.add_argument('--outf', type=str, default='generated_code.py',
                    help='output file for generated text')
parser.add_argument('--words', type=int, default='1000',
                    help='number of words to generate')
parser.add_argument('--seed', type=int, default=1111,
                    help='random seed')
parser.add_argument('--cuda', action='store_true',
                    help='use CUDA')
parser.add_argument('--temperature', type=float, default=1.0,
                    help='temperature - higher will increase diversity')
parser.add_argument('--log-interval', type=int, default=100,
                    help='reporting interval')
args = parser.parse_args()

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
        self.load()

    def load(self, model_filename = args.checkpoint, wc_filename='../statistics/tf_count_with_type.txt'):
        with open(model_filename, 'rb') as f:
            self.model = torch.load(f)
            self.model.eval()
            if args.cuda:
                self.model.cuda()
            else:
                self.model.cpu()
            self.corpus = data.Corpus(args.data,wc_filename)
        print 'loaded!'

    def postprocess(self, word_idx, suggestion=1):
        # top 1 suggestion
        res = self.corpus.dictionary.idx2word[word_idx[0]]
        # 5 - indent++ 4 * indent spaces
        # 6 - indent -= 1
        while res[1] == '':
            print res
            if res[0] == 5:
                indent += 1
                return ['    ' * indent]
            elif res[0] == 6:
                indent -= 1
            input.data.fill_(word_idx[0])
            output, hidden = self.model(input, hidden)
            word_weights = output.squeeze().data.div(args.temperature).exp().cpu()
            word_idx = torch.topk(word_weights, suggestion)[1]
            res = self.corpus.dictionary.idx2word[word_idx[0]]
        print res
        return [res[1]]

    def predict_next(self, code,suggestion=1):
        ntokens = len(self.corpus.dictionary)
        hidden = self.model.init_hidden(1)
        input = Variable(torch.rand(1, 1).mul(ntokens).long(), volatile=True)
        if args.cuda:
            input.data = input.data.cuda()
        tokens = tokenizer.tokenize_wrapper(code)
        for token in tokens[:-1]:
            word_idx = self.corpus.dictionary.word2idx.get(token, 0)
            input.data.fill_(word_idx)
            output, hidden = self.model(input, hidden)
        word_weights = output.squeeze().data.div(args.temperature).exp().cpu()
        word_idx = torch.topk(word_weights, suggestion)[1]
        res = self.postprocess(word_idx, suggestion)
        return res

def generate(model, corpus, tokens = ""):
    global hidden,indent
    test(model, corpus, tokens)
    symbols = ['.','(',')',',','[',']','{','}']
    ntokens = len(corpus.dictionary)
    hidden = model.init_hidden(1)
    input = Variable(torch.rand(1, 1).mul(ntokens).long(), volatile=True)
    if args.cuda:
        input.data = input.data.cuda()
    with open(args.outf, 'w') as outf:
        outf.write(tokens)
        prev_word = None
        for i in range(args.words):
            output, hidden = model(input, hidden)
            word_weights = output.squeeze().data.div(args.temperature).exp().cpu()
            word_idx = torch.multinomial(word_weights, 1)[0]
            input.data.fill_(word_idx)
            word = corpus.dictionary.idx2word[word_idx]
            if word[0] == 5:
                indent += 1
                word = word[1]
            elif word[0] == 6:
                indent -= 1
                word = word[1]
            elif word[1] == '\n':
                word = '\n' + ' ' * 4 * indent
            else:
                word = word[1]
            outf.write((('' if word in symbols  or prev_word in symbols else ' '))+word)
            prev_word = word
            if i % args.log_interval == 0:
                print('| Generated {}/{} words'.format(i, args.words))
if __name__ == '__main__':
    # f = open('../raw_data/10729_annotations.py','r')
    test = Test()
    print test.predict_next("for i in ")
    # model, corpus = load(args.checkpoint)
    # print test(model, corpus, "for i in ",40)
    # generate(model, corpus, "import tensorflow")
