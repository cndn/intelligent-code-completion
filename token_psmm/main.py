import torch
import argparse
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import numpy as np
from torch.utils.data import *
from torch.autograd import *
# import training_monitor.logger as tmlog
import preprocess
from batchify import *
from model import *
import data

parser = argparse.ArgumentParser("Pointer Sentinel Mixture Models")
parser.add_argument('--batch-size', type=int, default=32)
parser.add_argument('--lr', type=float, default=1)
parser.add_argument('--cuda', action='store_true')
parser.add_argument('--epochs', type=int, default=30)
parser.add_argument('--hidden', type=int, default=650)
parser.add_argument('--data', type=str, default='',
                    help='location of the data corpus')
args = parser.parse_args()

# logger = tmlog.Logger('../runs/psmm')

# c = preprocess.Corpus()
c = data.Corpus(args.data, '../statistics/tf_count_with_type.txt')
train_batch = Batchify(c.train, args.batch_size)
valid_batch = Batchify(c.valid, args.batch_size)
test_batch = Batchify(c.test, args.batch_size)
model = PSMM(args.batch_size, len(c.dict), args.hidden, args.cuda)
if args.cuda:
    model = model.cuda()

optimizer = optim.SGD(model.parameters(), lr=args.lr, momentum=0.9, weight_decay=1e-5)
min_ppl = 1e9

for epoch in range(args.epochs):
    model.train()
    model.reset_hidden()
    log_ppl = 0
    for idx, (data, label) in enumerate(train_batch, 1):
        result, ptr_rst = model(data)
        label = Variable(label.view(-1))
        if args.cuda:
            label = label.cuda()

        loss = F.nll_loss(result, label)
        loss_tot = loss + F.nll_loss(ptr_rst, label)
        log_ppl += loss.data[0]
        ppl = np.exp(loss.data[0])
        optimizer.zero_grad()
        loss_tot.backward()
        nn.utils.clip_grad_norm(model.parameters(), 1)
        optimizer.step()
        print "Epoch {}/{}, batch {}/{}: Perplexity: {}".format(epoch, args.epochs, idx, len(train_batch), ppl)

    log_ppl /= len(train_batch)
    ppl = np.exp(log_ppl)
    print "Train perplexity: {}".format(ppl)
    # logger.add_scalar('train_ppl', ppl, epoch)

    model.eval()
    model.reset_hidden()
    log_ppl = 0
    for data, label in valid_batch:
        result, _ = model(data)
        label = Variable(label.view(-1))
        if args.cuda:
            label = label.cuda()

        log_ppl += F.nll_loss(result, label).data[0]

    log_ppl /= len(valid_batch)
    ppl = np.exp(log_ppl)
    print "Evaluation perplexity: {}".format(ppl)
    # logger.add_scalar('eval_ppl', ppl, epoch)

    if ppl < min_ppl:
        min_ppl = ppl
        with open('../params/model.params', 'wb') as f:
            torch.save(model.state_dict(), f)
    else:
        for param_group in optimizer.param_groups:
            param_group['lr'] /= 4.0

model.eval()
model.reset_hidden()
log_ppl = 0
for data, label in test_batch:
    result, _ = model(data)
    label = Variable(label.view(-1))
    if args.cuda:
        label = label.cuda()

    log_ppl += F.nll_loss(result, label).data[0]

log_ppl /= len(test_batch)
ppl = np.exp(log_ppl)
print "Test perplexity: {}".format(ppl)

