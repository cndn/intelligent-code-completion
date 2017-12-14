train_set = open('valid.txt','r')
tf_set = open('tf_valid.txt','w')
for line in train_set:
    fn = '../raw_data/' + line.strip()
    if 'tensorflow' in open(fn, 'r').read():
        tf_set.write(fn + '\n')
    