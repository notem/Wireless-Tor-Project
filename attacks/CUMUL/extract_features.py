import os
import argparse
import numpy as np
from data_utils import load_dataset, log
from attacks import ATTACKS


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract feature vectors')
    parser.add_argument('--traces', type=str, help='Traces.',
                        required=True)
    parser.add_argument('--out', type=str, help='Output directory.',
                        required=True)
    args = parser.parse_args()

    X, Y, W, Npages, Nloads = load_dataset(args.traces)

    attack = ATTACKS["CUMUL"]()

    log('Extracting features')
    X_f = attack.extract_features(X, Y)

    log('Length of a feature vector: {}'.format(len(X_f)))

    if not os.path.isdir(args.out):
        log('Creating directory {}'.format(args.out))
        os.makedirs(args.out)

    log('Storing features into {}'.format(args.out))
    for x, w in zip(X_f, W):
        fname = os.path.join(args.out, w) + '.features'
        np.savetxt(fname, x, delimiter=',')
