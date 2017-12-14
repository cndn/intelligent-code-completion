#-# coding: utf-8-

import dynet as dy
import numpy as np
import argparse
import pickle
import codecs
import itertools
import random
import math
import os
import glob
import hashlib
import heapq

from contextlib import contextmanager
from collections import defaultdict
from itertools import chain
from parso.python.token import (tok_name, ENDMARKER, STRING, NUMBER, NAME, INDENT, opmap)
from parso.python.tokenize import tokenize, PythonToken


@contextmanager
def parameters(*params):
    yield tuple(map(lambda x: dy.parameter(x), params))


class Linear(object):
    def __init__(self, model, input_dim, output_dim):
        model = self.model = model.add_subcollection(self.__class__.__name__)
        self.spec = input_dim, output_dim

        self.W = model.add_parameters((output_dim, input_dim))
        self.b = model.add_parameters(output_dim)

    @classmethod
    def from_spec(cls, spec, model):
        input_dim, output_dim = spec
        return cls(model, input_dim, output_dim)

    def param_collection(self):
        return self.model

    def __call__(self, input_expr):
        with parameters(self.W, self.b) as (W, b):
            return dy.affine_transform([b, W, input_expr])


class Attender(object):
    def __init__(self, model, query_dim, content_dim, att_dim):
        model = self.model = model.add_subcollection(self.__class__.__name__)
        self.spec = query_dim, content_dim, att_dim

        self.P = model.add_parameters((att_dim, content_dim))
        self.W = model.add_parameters((att_dim, query_dim))
        self.b = model.add_parameters((1, att_dim))

    @classmethod
    def from_spec(cls, spec, model):
        query_dim, content_dim, att_dim = spec
        return cls(model, query_dim, content_dim, att_dim)

    def param_collection(self):
        return self.model

    def __call__(self):
        with parameters(self.P, self.W, self.b) as (P, W, b):
            ps = []

            def append_e(e):
                ps.append(P * e)
                return len(ps) - 1

            def cal_scores(s):
                if len(ps) == 0:
                    return None
                hs_matrix = dy.tanh(dy.colwise_add(dy.concatenate_cols(ps), W * s))
                return dy.softmax(dy.transpose(b * hs_matrix))

            return cal_scores, append_e


class Embedder(object):
    def __init__(self, model, vocab, embed_dim):
        model = self.model = model.add_subcollection(self.__class__.__name__)
        self.spec = vocab, embed_dim

        self.wid2word = [None] + sorted(set(vocab))
        self.word2wid = {word: wid for wid, word in enumerate(self.wid2word)}

        self.embeds = model.add_lookup_parameters((len(self.wid2word), embed_dim))

    @classmethod
    def from_spec(cls, spec, model):
        vocab, embed_dim = spec
        return cls(model, vocab, embed_dim)

    def param_collection(self):
        return self.model

    def get_wid(self, word):
        return self.word2wid[word] if word in self.word2wid else 0

    def __getitem__(self, word):
        return self.embeds[self.get_wid(word)]

    def __call__(self, seq):
        return [self[x] for x in seq]


class Hasher(object):
    def __init__(self, model, byte_embed_dim, hash_dim):
        model = self.model = model.add_subcollection(self.__class__.__name__)
        self.spec = byte_embed_dim, hash_dim

        self.byte_embeds = Embedder(model, range(256), byte_embed_dim)
        self.hashLSTM = dy.BiRNNBuilder(1, byte_embed_dim, hash_dim, model, dy.LSTMBuilder)

    @classmethod
    def from_spec(cls, spec, model):
        byte_embed_dim, hash_dim = spec
        return cls(model, byte_embed_dim, hash_dim)

    def param_collection(self):
        return self.model

    def __call__(self, text):
        byte_seq = bytearray(chr(0) + text, 'utf-8')
        if len(byte_seq) >= 32:
            byte_seq = hashlib.sha256(byte_seq).digest()
        return self.hashLSTM.transduce(self.byte_embeds(byte_seq))[-1]


class Decoder(object):
    def __init__(self, model, type_vocabs, copyable_types, type_embed_dim, literal_embed_dim, byte_embed_dim, hash_dim, att_dim, num_layers, hidden_dim):
        model = self.model = model.add_subcollection(self.__class__.__name__)
        self.spec = type_vocabs, copyable_types, type_embed_dim, literal_embed_dim, byte_embed_dim, hash_dim, att_dim, num_layers, hidden_dim

        type_vocabs = sorted([(token_type, type_vocab if len(type_vocab) > 2 else set()) for token_type, type_vocab in type_vocabs.items()])
        copyable_types = sorted(copyable_types)
        self.hasher = Hasher(model, byte_embed_dim, hash_dim)
        self.type_embeds = Embedder(model, sorted(tok_name.keys()), type_embed_dim)
        self.literal_embeds = {token_type: Embedder(model, type_vocab, literal_embed_dim) for token_type, type_vocab in type_vocabs}
        self.copy_atts = {token_type: Attender(model, hidden_dim, hidden_dim, att_dim) for token_type in copyable_types}

        self.h2type = Linear(model, hidden_dim, len(tok_name))
        self.h2copy = {token_type: Linear(model, hidden_dim, 1) for token_type in copyable_types}
        self.h2vocab = {token_type: Linear(model, hidden_dim, len(type_vocab) + 1) for token_type, type_vocab in type_vocabs}
        self.langLSTM = dy.LSTMBuilder(num_layers, type_embed_dim + literal_embed_dim + hash_dim, hidden_dim, model)

    @classmethod
    def from_spec(cls, spec, model):
        type_vocabs, copyable_types, type_embed_dim, literal_embed_dim, byte_embed_dim, hash_dim, att_dim, num_layers, hidden_dim = spec
        return cls(model, type_vocabs, copyable_types, type_embed_dim, literal_embed_dim, byte_embed_dim, hash_dim, att_dim, num_layers, hidden_dim)

    def param_collection(self):
        return self.model

    def set_dropout(self, p):
        self.langLSTM.set_dropout(p)

    def disable_dropout(self):
        self.langLSTM.disable_dropout()

    def __call__(self, hash_cache=None):
        if hash_cache is None:
            hash_cache = {}
        s = [self.langLSTM.initial_state()]
        copy_atts = {token_type: att() for token_type, att in self.copy_atts.items()}
        copy_history = {token_type: defaultdict(list) for token_type in self.copy_atts}

        def hash(text):
            if text not in hash_cache:
                hash_cache[text] = self.hasher(text)
            return hash_cache[text]

        def next_state(token_type, token_literal):
            s[0] = s[0].add_input(dy.concatenate([self.type_embeds[token_type], self.literal_embeds[token_type][token_literal], hash(token_literal)]))
            if token_type in copy_atts:
                copy_index = copy_atts[token_type][1](s[0].output())
                copy_history[token_type][token_literal].append(copy_index)
            return s[0]

        def type_probs():
            h = s[0].output()
            return dy.softmax(self.h2type(h))

        def type_probs_pick(token_type):
            probs = type_probs()
            tid = self.type_embeds.get_wid(token_type)
            return dy.pick(probs, tid)

        def copy_prob(token_type):
            if token_type not in copy_atts:
                return dy.scalarInput(0.0)
            h = s[0].output()
            return dy.logistic(self.h2copy[token_type](h))

        def vocab_probs(token_type):
            assert token_type in self.h2vocab
            h = s[0].output()
            return dy.softmax(self.h2vocab[token_type](h))

        def vocab_probs_pick(token_type, token_literal):
            if token_type not in self.h2vocab:
                return dy.scalarInput(1.0)
            probs = vocab_probs(token_type)
            wid = self.literal_embeds[token_type].get_wid(token_literal)
            return dy.pick(probs, wid)

        def copy_src_probs(token_type):
            assert token_type in copy_atts
            assert any(len(indexes) > 0 for indexes in copy_history[token_type].values())
            h = s[0].output()
            return copy_atts[token_type][0](h)

        def copy_src_probs_map(token_type, lazy=False):
            if token_type not in copy_atts:
                return {}
            literal_history = copy_history[token_type]
            if all(len(history) == 0 for history in literal_history.values()):
                return {}
            probs = copy_src_probs(token_type)
            if lazy:
                return {literal: dy.sum_elems(dy.select_rows(probs, history)) for literal, history in literal_history.items() if len(history) > 0}
            return {literal: dy.sum_elems(dy.select_rows(probs, history)).value() for literal, history in literal_history.items() if len(history) > 0}


        def copy_src_probs_pick(token_type, token_literal):
            if token_type not in copy_atts:
                return dy.scalarInput(0.0)
            selected_indexes = copy_history[token_type][token_literal]
            if len(selected_indexes) == 0:
                return dy.scalarInput(0.0)
            probs = copy_src_probs(token_type)
            return dy.sum_elems(dy.select_rows(probs, selected_indexes))

        next_state(ENDMARKER, '')

        return next_state, type_probs, type_probs_pick, copy_prob, vocab_probs, vocab_probs_pick, copy_src_probs, copy_src_probs_map, copy_src_probs_pick


def tokenize_without_endmarker(code):
    safeword = 'ZZZ_USER_WANTS_TO_COMPLETE_HERE'
    for token in tokenize(code + safeword, (2, 7)):
        if token.string == safeword:
            return
        elif token.string.endswith(safeword):
            yield PythonToken(token.type, token.string[:-len(safeword)], token.start_pos, token.prefix)
            return
        else:
            yield token


def tokenize_without_empty_tail(code):
    result = list(tokenize_without_endmarker(code))
    while result:
        if len(result[-1].string) == 0 and len(result[-1].prefix) == 0 and result[-1].type != INDENT:
            del result[-1]
        else:
            break
    return [(token.type, token.string) for token in result]


def cal_loss(decoder, hash_cache, tokens):
    next_state, _, type_probs_pick, copy_prob, _, vocab_probs_pick, _, _, copy_src_probs_pick = decoder(hash_cache)
    losses = []
    for token_type, token_literal in tokens:
        type_p = type_probs_pick(token_type)
        copy_p = copy_prob(token_type)
        literal_p = copy_p * copy_src_probs_pick(token_type, token_literal) + (1.0 - copy_p) * vocab_probs_pick(token_type, token_literal)
        token_loss = -(dy.log(type_p) + dy.log(literal_p))
        losses.append(token_loss)
        next_state(token_type, token_literal)
    return dy.esum(losses)


def predict(decoder, tokens):
    dy.renew_cg()
    next_state, type_probs, _, copy_prob, vocab_probs, _, copy_src_probs, copy_src_probs_map, _ = decoder({})
    for token_type, token_literal in tokens:
        next_state(token_type, token_literal)
    type_p = type_probs().npvalue()
    next_type = decoder.type_embeds.wid2word[type_p.argmax()]
    if next_type not in decoder.h2vocab:
        return next_type, None
    copy_p = copy_prob(next_type).value()
    vocab_p = (1.0 - copy_p) * vocab_probs(next_type).npvalue()
    copy_src_p_map = copy_src_probs_map(next_type)
    literal_embed = decoder.literal_embeds[next_type]
    max_unk_literal = None
    max_unk_copy_p = 0.0
    for token_literal, copy_literal_p in copy_src_p_map.items():
        wid = literal_embed.get_wid(token_literal)
        if wid == 0 and max_unk_copy_p < copy_literal_p:
            max_unk_copy_p = copy_literal_p
            max_unk_literal = token_literal
        vocab_p[wid] += copy_p * copy_literal_p
    next_wid = vocab_p.argmax()
    if next_wid == 0:
        if max_unk_literal is not None:
            return next_type, max_unk_literal
        else:
            vocab_p[0] = -np.inf
            next_wid = vocab_p.argmax()
    return next_type, literal_embed.wid2word[next_wid]


def accuracy(decoder, tokens):
    dy.renew_cg()
    next_state, type_probs, _, copy_prob, vocab_probs, _, copy_src_probs, copy_src_probs_map, _ = decoder({})
    def predict_next():
        type_p = type_probs().npvalue()
        next_type = decoder.type_embeds.wid2word[type_p.argmax()]
        if next_type not in decoder.h2vocab:
            return next_type, None
        copy_p = copy_prob(next_type).value()
        vocab_p = (1.0 - copy_p) * vocab_probs(next_type).npvalue()
        copy_src_p_map = copy_src_probs_map(next_type)
        literal_embed = decoder.literal_embeds[next_type]
        max_unk_literal = None
        max_unk_copy_p = 0.0
        for token_literal, copy_literal_p in copy_src_p_map.items():
            wid = literal_embed.get_wid(token_literal)
            if wid == 0 and max_unk_copy_p < copy_literal_p:
                max_unk_copy_p = copy_literal_p
                max_unk_literal = token_literal
            vocab_p[wid] += copy_p * copy_literal_p
        next_wid = vocab_p.argmax()
        if next_wid == 0:
            if max_unk_literal is not None:
                return next_type, max_unk_literal
            else:
                vocab_p[0] = -np.inf
                next_wid = vocab_p.argmax()
        return next_type, literal_embed.wid2word[next_wid]
    def compare(token1, token2):
        token1_type, token1_literal = token1
        token2_type, token2_literal = token2
        if token1_type != token2_type:
            return False
        if token1_type not in (NAME, NUMBER, STRING):
            return True
        return token1_literal == token2_literal
    correct = 0.0
    correct += compare(predict_next(), tokens[0])
    for current_token, next_token in zip(tokens, tokens[1:]):
        token_type, token_literal = current_token
        next_state(token_type, token_literal)
        correct += compare(predict_next(), next_token)
    return correct


def main():
    parser = argparse.ArgumentParser(description='Train attention model')
    parser.add_argument('--model_path', default=None, type=str)
    parser.add_argument('--checkpoint_dir', default='./checkpoints', type=str)
    parser.add_argument('--train_set', default='./train_set', type=str)
    parser.add_argument('--train_set_dmp', default='./train_set.dmp', type=str)
    parser.add_argument('--valid_set', default='./valid_set', type=str)
    parser.add_argument('--valid_set_dmp', default='./valid_set_dmp', type=str)
    parser.add_argument('--vocab_path', default='./vocab.dmp', type=str)
    parser.add_argument('--unk_threshold', default=20, type=int)
    parser.add_argument('--batch_size', default=8, type=int)
    parser.add_argument('--trainer', default='adam', choices={'sgd', 'adam', 'adagrad'}, type=str)
    parser.add_argument('--type_embed_dim', default=128, type=int)
    parser.add_argument('--literal_embed_dim', default=128, type=int)
    parser.add_argument('--byte_embed_dim', default=64, type=int)
    parser.add_argument('--hash_dim', default=64, type=int)
    parser.add_argument('--att_dim', default=64, type=int)
    parser.add_argument('--num_layers', default=2, type=int)
    parser.add_argument('--hidden_dim', default=256, type=int)
    parser.add_argument('--dropout', default=None, type=float)
    parser.add_argument('--seed', default=11927, type=int)

    args, _ = parser.parse_known_args()

    if not os.path.exists(args.train_set_dmp):
        train_set = []
        for path in glob.glob('%s/*.py' % args.train_set):
            with codecs.open(path, 'r', 'utf-8') as f:
                train_set.append(tokenize_without_empty_tail(f.read()))
        with open(args.train_set_dmp, 'wb') as f:
            pickle.dump(train_set, f)
    else:
        with open(args.train_set_dmp, 'rb') as f:
            train_set = pickle.load(f)
    train_set = [tokens for tokens in train_set if len(tokens) < 4000]

    print('size of train_set:', len(train_set))

    token_literal_counters = defaultdict(lambda : defaultdict(int))
    for token_type, token_literal in chain(*map(set, train_set)):
        token_literal_counters[token_type][token_literal] += 1

    if not os.path.exists(args.vocab_path):
        type_vocabs = {token_type: {literal for literal, count in literal_counters.items() if count > args.unk_threshold} for token_type, literal_counters in token_literal_counters.items()}
        for token_type in tok_name:
            if token_type not in type_vocabs:
                type_vocabs[token_type] = set()
        with open(args.vocab_path, 'wb') as f:
            pickle.dump(type_vocabs, f)
    else:
        with open(args.vocab_path, 'rb') as f:
            type_vocabs = pickle.load(f)
    print('vocab_types:', {tok_name[token_type]: len(type_vocab) for token_type, type_vocab in type_vocabs.items() if len(type_vocab) > 2})

    copyable_types = {STRING, NAME, NUMBER}
    print('copyable_types:', {tok_name[token_type] for token_type in copyable_types})


    if not os.path.exists(args.valid_set_dmp):
        valid_set = []
        for path in glob.glob('%s/*.py' % args.valid_set):
            with codecs.open(path, 'r', 'utf-8') as f:
                valid_set.append(tokenize_without_empty_tail(f.read()))
        with open(args.valid_set_dmp, 'wb') as f:
            pickle.dump(valid_set, f)
    else:
        with open(args.valid_set_dmp, 'rb') as f:
            valid_set = pickle.load(f)

    print('size of valid_set:', len(valid_set))

    random.seed(args.seed)

    model = dy.ParameterCollection()

    if args.trainer == 'sgd':
        trainer = dy.SimpleSGDTrainer(model)
    elif args.trainer == 'adam':
        trainer = dy.AdamTrainer(model)
    elif args.trainer == 'adagrad':
        trainer = dy.AdagradTrainer(model)

    decoder = Decoder(model, type_vocabs, copyable_types, args.type_embed_dim, args.literal_embed_dim, args.byte_embed_dim, args.hash_dim, args.att_dim, args.num_layers, args.hidden_dim)

    if not os.path.exists(args.checkpoint_dir):
        os.makedirs(args.checkpoint_dir)

    if args.model_path is None:
        model.save('%s/init.dmp' % args.checkpoint_dir)
    else:
        model.populate(args.model_path)

    if args.dropout is not None:
        decoder.set_dropout(args.dropout)

    num_samples = len(train_set)
    for num_epoch in itertools.count(1):
        random.shuffle(train_set)
        epoch_loss = 0.0
        epoch_seq_length = 0
        batch_losses = []
        hash_cache = {}
        batch_seq_length = 0
        num_batch = 0
        dy.renew_cg()
        for i, (tokens) in enumerate(train_set, 1):
            print('batch', i, len(tokens))
            loss = cal_loss(decoder, hash_cache, tokens)
            batch_losses.append(loss)
            batch_seq_length += len(tokens)
            epoch_seq_length += len(tokens)
            if i % args.batch_size == 0 or i == num_samples:
                batch_loss = dy.esum(batch_losses) / len(batch_losses)
                batch_loss.backward()
                trainer.update()
                batch_loss_value = batch_loss.value()
                epoch_loss += batch_loss_value
                dy.renew_cg()
                num_batch += 1
                batch_losses = []
                hash_cache = {}
                if num_batch % 20 == 0:
                    batch_per_item_loss = batch_loss_value / batch_seq_length
                    epoch_perplexity = math.exp(epoch_loss / epoch_seq_length)
                    print('epoch %d, batch %d, batch_per_item_loss %f, epoch_perplexity %f' % \
                          (num_epoch, num_batch, batch_per_item_loss, epoch_perplexity))
                batch_seq_length = 0
        model.save('%s/epoch_%d.dmp' % (args.checkpoint_dir, num_epoch))


# python model.py --dynet-autobatch 1 --dynet-mem 2000 --dynet-gpu --batch_size 64 --dropout 0.7
if __name__ == "__main__":
    main()
