import torch

class Batchify(object):
    def __init__(self, seqs, bts):
        self.seqs = seqs
        self.bts = bts
        self.__cnt = 0

    def __iter__(self):
        return self

    def next(self):
        self.__cnt += 1
        if self.__cnt > self.__len__():
            self.__cnt = 0
            raise StopIteration
        current_batch = [self.seqs[self.__cnt - 1 + i * self.__len__()] for i in range(self.bts)]
        batch = torch.LongTensor(current_batch).transpose(0, 1).contiguous()
        return batch[:-1], batch[1:]

    def __len__(self):
        return len(self.seqs) // self.bts
