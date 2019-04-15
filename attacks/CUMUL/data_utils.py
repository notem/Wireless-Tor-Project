import os
import json
import numpy as np


def log(s):
    print('[*] {}'.format(s))


def load_packet_sequence(fname, delimiter='\t'):
    """Loads a packet sequence from a file.

    The file should contain, one per line, the time and size
    of each packet separated by '\t'.
    Negative sizes indicate incoming packets, positive indicate
    outgoing packets.

    A packet sequence is a list in the form:
        [[t1, s1], [t2, s2], ...],
    where ti and si are respectively the time and size of the
    i-th packet in the sequence.
    """
    ps = [[], []]
    with open(fname, 'r') as f:
        for line in f:
            time, size = line.split(delimiter)
            if abs(int(size)) > 512:
                ps[0].append(float(time))
                ps[1].append(int(size))

    return ps


def load_dataset(folder):
    """Creates a dataset from files of packet sequences within the
    specified folder.  Each file "w-n" represents the packet sequence
    of n-th load of w-th webpage.  A file is in the format specified in
    load_packets_sequence().  Returns a list of traces and a list with
    the respective labels.
    """
    sequences = []  # List of packet sequences.
    labels = []  # List of labels (webpage ids).
    wid = []  # List of webpage-load ids.

    log('Loading traces from {}'.format(folder))
    files = [os.path.join(root, f) for root, dirs, files in os.walk(folder) for f in files]
    # Hack to remove unwanted files (unmonitored dataset) from Wang14 dataset:
    files = [x for x in files if os.path.basename(x).find('_') != -1]

    d = dict()
    for f in files:
        f_base = os.path.basename(f)
        # A file is considered only if its name is in the format
        # "page_id-load_id".
        page_id, load_id = f_base.split('_')
        d[page_id] = (d[page_id] if d.get(page_id, None) is not None else 0) + 1
        p = load_packet_sequence(f)
        sequences.append(p)
        labels.append(int(page_id))
        wid.append("{}-{}".format(page_id, d[page_id]))

    n_pages = len(set(labels))
    n_loads = -1
    log('Loaded {} pages, {} loads each'.format(n_pages, n_loads))
    log('Number of objects: {}'.format(len(sequences)))

    return sequences, labels, wid, n_pages, n_loads


def load_features(folder):
    """
    """
    log('Loading features from {}'.format(folder))
    feature_vecs = []  # List of feature vectors.
    labels = []  # List of labels (webpage ids).
    wid = []  # List of webpage-load ids.

    files = [os.path.join(folder, x) for x in os.listdir(folder)]
    files = [x for x in files if x.endswith('.features')]

    for f in files:
        f_base = os.path.basename(f).replace('.features', '')
        # A file is considered only if its name is in the format
        # "page_id-load_id".
        try:
            page_id, load_id = f_base.split('-')
            f = np.genfromtxt(f, delimiter=',').reshape(1, -1)
            feature_vecs.append(f)
            labels.append(int(page_id))
            wid.append(f_base)
        except:
            pass

    X = np.vstack(feature_vecs)
    labels = np.array(labels)
    n_pages = len(set(labels))
    n_loads = -1

    log('Loaded {} pages, {} loads each'.format(n_pages, n_loads))
    log('Number of objects: {}'.format(len(X)))
    log('Length of a feature vector: {}'.format(X.shape[1]))

    return X, labels, wid, n_pages, n_loads


def store_results(fname, results):
    """Stores a dictionary of results into a json file.
    """
    with open(fname, 'w') as f:
        json.dump(results, f, sort_keys=True, indent=4, separators=(',', ': '))
