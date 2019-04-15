import os
import numpy as np


def load_data(directory, delimiter='\t', file_split="_", length=5000):
    """
    Load data from ascii files
    """
    X, y = [], []
    y_count = dict()
    for root, dirs, files in os.walk(directory):
        for fname in files:
            try:
                # trace_class is derived from file name (eg. 'C-n' where C is class and n is instance)
                trace_class = int(fname.split(file_split)[0])
                y_count[trace_class] = y_count.get(trace_class, 0) + 1

                # build direction sequence
                sequence = load_trace(os.path.join(root, fname), seperator=delimiter)
                sequence = sequence[1]  # use only direction

                # add sequence and label
                sequence = np.array(sequence)
                sequence.resize((length, 1))
                X.append(sequence)
                y.append(trace_class)
            except:
                pass

    # wrap as numpy array
    X, Y = np.array(X), np.array(y)

    # shuffle
    s = np.arange(Y.shape[0])
    np.random.seed(0)
    np.random.shuffle(s)
    X, Y = X[s], Y[s]
    return X, Y


def load_trace(path, seperator="\t"):
    """
    loads data to be used for predictions
    """
    file = open(path, 'r')
    sequence = [[], []]
    for line in file:
        try:
            pieces = line.strip("\n").split(seperator)
            if int(pieces[1]) == 0:
                break
            timestamp = float(pieces[0])
            length = abs(int(pieces[1]))
            direction = int(pieces[1]) // length
            if length > 512:
                sequence[0].append(timestamp)
                sequence[1].append(direction)
        except Exception as e:
            print(e)
            print("Error when trying to read packet sequence from %s!" % path)
            return None
    return sequence


