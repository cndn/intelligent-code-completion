train_set = open('train.txt','r')
tf_set = open('tf_train.txt','w')
for line in train_set:
    fn = '../raw_data/' + line.strip()
    if 'tensorflow' in open(fn, 'r').read():
        tf_set.write(fn + '\n')
    