import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.autograd import *

class PSMM(nn.Module):
    def __init__(self, batch_size, vocab_size, hidden_size, use_cuda):
        super(PSMM, self).__init__()
        self.batch_size = batch_size
        self.vocab_size = vocab_size
        self.use_cuda = use_cuda
        self.hidden_size = hidden_size
        self.embed = nn.Embedding(vocab_size, hidden_size)
        self.affine1 = nn.Linear(hidden_size, vocab_size)
        self.affine2 = nn.Linear(hidden_size, hidden_size)
        self.rnn = nn.LSTMCell(hidden_size, hidden_size)
        self.sentinel_vector = Variable(torch.zeros(hidden_size, 1), requires_grad=True)
        if self.use_cuda:
            self.sentinel_vector = self.sentinel_vector.cuda()
        self.init_weight()
        self.reset_hidden()

    def reset_hidden(self):
        self.hidden = None
        self.cell = None

    def init_weight(self):
        init_range = 0.1
        self.embed.weight.data.uniform_(-init_range, init_range)
        self.affine1.weight.data.uniform_(-init_range, init_range)
        self.affine1.bias.data.fill_(0)
        self.affine2.weight.data.uniform_(-init_range, init_range)
        self.affine2.bias.data.fill_(0)
        self.sentinel_vector.data.uniform_(-init_range, init_range)
    
    """
        Input size:
        length * batch_size
    """
    def forward(self, input, hidden):
        probs = []
        # hiddens = []
        
        # hidden, cell = torch.FloatTensor(self.batch_size, self.hidden_size).fill_(0), \
        #                torch.FloatTensor(self.batch_size, self.hidden_size).fill_(0)
        # if self.use_cuda:
        #     hidden, cell = Variable(hidden).cuda(), Variable(cell).cuda()
        # else:
        #     hidden, cell = Variable(hidden), Variable(cell)

        length = input.size(0)

        cumulate_matrix = torch.zeros((length, self.batch_size, self.vocab_size))
        cumulate_matrix.scatter_(2, input.unsqueeze(2).data, 1.0)
        if self.use_cuda:
            cumulate_matrix = cumulate_matrix.cuda()
            input = input.cuda()
        
        ptr_scores = []
        for step in range(length):
            embed = self.embed(input[step])
            print hidden
            _, hidden = self.rnn(embed, hidden)
            hiddens.append(hidden)
            query = F.tanh(self.affine2(hidden))
            z = []
            for j in range(step + 1):
                z.append(torch.sum(hiddens[j] * query, 1).view(-1))
            z.append(torch.mm(query, self.sentinel_vector).view(-1))
            z = torch.stack(z)
            a = F.softmax(z.transpose(0, 1)).transpose(0, 1)
            prefix_matrix = cumulate_matrix[:step + 1]
            p_ptr = torch.sum(Variable(prefix_matrix) * a[:-1].unsqueeze(2).expand_as(prefix_matrix), 0).squeeze(0)
            output = self.affine1(hidden)
            p_vocab = F.softmax(output)
            p = p_ptr + p_vocab * a[-1].unsqueeze(1).expand_as(p_vocab)
            probs.append(p)
            ptr_scores.append(p_ptr + a[-1].unsqueeze(1))

        return torch.log(torch.cat(probs).view(-1, self.vocab_size)), torch.log(torch.cat(ptr_scores).view(-1, self.vocab_size))

    def init_hidden(self,bsz):
        return Variable(torch.FloatTensor(bsz, self.hidden_size).fill_(0))

class RNNModel(nn.Module):
    """Container module with an encoder, a recurrent module, and a decoder."""

    def __init__(self, rnn_type, ntoken, ninp, nhid, nlayers, dropout=0.5, tie_weights=False):
        super(RNNModel, self).__init__()
        self.drop = nn.Dropout(dropout)
        self.encoder = nn.Embedding(ntoken, ninp)
        if rnn_type in ['LSTM', 'GRU']:
            self.rnn = getattr(nn, rnn_type)(ninp, nhid, nlayers, dropout=dropout)
        else:
            try:
                nonlinearity = {'RNN_TANH': 'tanh', 'RNN_RELU': 'relu'}[rnn_type]
            except KeyError:
                raise ValueError( """An invalid option for `--model` was supplied,
                                 options are ['LSTM', 'GRU', 'RNN_TANH' or 'RNN_RELU']""")
            self.rnn = nn.RNN(ninp, nhid, nlayers, nonlinearity=nonlinearity, dropout=dropout)
        self.decoder = nn.Linear(nhid, ntoken)

        # Optionally tie weights as in:
        # "Using the Output Embedding to Improve Language Models" (Press & Wolf 2016)
        # https://arxiv.org/abs/1608.05859
        # and
        # "Tying Word Vectors and Word Classifiers: A Loss Framework for Language Modeling" (Inan et al. 2016)
        # https://arxiv.org/abs/1611.01462
        if tie_weights:
            if nhid != ninp:
                raise ValueError('When using the tied flag, nhid must be equal to emsize')
            self.decoder.weight = self.encoder.weight

        self.init_weights()

        self.rnn_type = rnn_type
        self.nhid = nhid
        self.nlayers = nlayers

    def init_weights(self):
        initrange = 0.1
        self.encoder.weight.data.uniform_(-initrange, initrange)
        self.decoder.bias.data.fill_(0)
        self.decoder.weight.data.uniform_(-initrange, initrange)

    def forward(self, input, hidden):
        emb = self.drop(self.encoder(input))
        output, hidden = self.rnn(emb, hidden)
        output = self.drop(output)
        decoded = self.decoder(output.view(output.size(0)*output.size(1), output.size(2)))
        return decoded.view(output.size(0), output.size(1), decoded.size(1)), hidden

    def init_hidden(self, bsz):
        weight = next(self.parameters()).data
        if self.rnn_type == 'LSTM':
            return (Variable(weight.new(self.nlayers, bsz, self.nhid).zero_()),
                    Variable(weight.new(self.nlayers, bsz, self.nhid).zero_()))
        else:
            return Variable(weight.new(self.nlayers, bsz, self.nhid).zero_())