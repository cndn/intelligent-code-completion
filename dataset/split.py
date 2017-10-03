from random import shuffle

def split():
    TRAIN_RATIO = 0.6
    VALID_RATIO = 0.2
    TEST_RATIO = 0.2
    train = open('train.txt','w')
    test = open('test.txt','w')
    valid = open('valid.txt','w')
    id2filename = open('../raw_data/id2filename.txt','r')
    idmap = {}
    for line in id2filename:
        id, filename = line.strip().split('\\')
        idmap[int(id)] = filename
    l = range(1, len(idmap)+1)
    shuffle(l)
    for i in range(int(len(l) * TRAIN_RATIO)):
        train.write(idmap[l[i]] + '\n')
    for i in range(int(len(l) * TRAIN_RATIO), int(len(l) * (TRAIN_RATIO + VALID_RATIO))):
        valid.write(idmap[l[i]] + '\n')
    for i in range(int(len(l) * (TRAIN_RATIO + VALID_RATIO)), len(l)):
        test.write(idmap[l[i]] + '\n')


if __name__ == '__main__':
    split()

