import random
import sys
import argparse
import os
import numpy as np

from keras.models import Sequential
from keras.layers import Conv1D, MaxPooling1D, BatchNormalization
from keras.layers.core import Activation, Flatten, Dense, Dropout
from keras.initializers import glorot_uniform
from keras.optimizers import Adamax
from keras.wrappers.scikit_learn import KerasClassifier
from sklearn.model_selection import GridSearchCV

random.seed(0)


# define the ConvNet
class ConvNet:
    @staticmethod
    def build(classes,
              input_shape,
              activation_function="relu",
              filter_num=('None', 32, 64, 128, 256),
              kernel_size=8,
              conv_stride_size=1,
              pool_stride_size=1,
              pool_size=8,
              fc_layer_size=('None', 512, 512)):

        # Sequential Keras model template
        model = Sequential()

        # add convolutional layer blocks
        for block_no in range(1, len(filter_num)):
            if block_no == 1:
                model.add(Conv1D(filters=filter_num[block_no],
                                 kernel_size=kernel_size,
                                 input_shape=input_shape,
                                 strides=conv_stride_size,
                                 padding='same',
                                 name='block{}_conv1'.format(block_no)))
            else:
                model.add(Conv1D(filters=filter_num[block_no],
                                 kernel_size=kernel_size,
                                 strides=conv_stride_size,
                                 padding='same',
                                 name='block{}_conv1'.format(block_no)))

            model.add(BatchNormalization())

            model.add(Activation(activation_function, name='block{}_act1'.format(block_no)))

            model.add(Conv1D(filters=filter_num[block_no],
                             kernel_size=kernel_size,
                             strides=conv_stride_size,
                             padding='same',
                             name='block{}_conv2'.format(block_no)))

            model.add(BatchNormalization())

            model.add(Activation(activation_function, name='block{}_act2'.format(block_no)))

            model.add(MaxPooling1D(pool_size=pool_size,
                                   strides=pool_stride_size,
                                   padding='same',
                                   name='block1_pool'))

            model.add(Dropout(0.1, name='block1_dropout'))

        # flatten output before fc layers
        model.add(Flatten(name='flatten'))

        # add fully-connected layers
        for layer_no in range(1, len(fc_layer_size)):
            model.add(Dense(fc_layer_size[layer_no],
                            kernel_initializer=glorot_uniform(seed=0),
                            name='fc{}'.format(layer_no)))

            model.add(BatchNormalization())
            model.add(Activation('relu', name='fc{}_act'.format(layer_no)))

            model.add(Dropout(0.7, name='fc{}_drop'.format(layer_no)))

        # add final classification layer
        model.add(Dense(classes, kernel_initializer=glorot_uniform(seed=0), name='fc_final'))
        model.add(Activation('softmax', name="softmax"))

        # compile model with Adamax optimizer
        optimizer = Adamax(lr=0.002, beta_1=0.9, beta_2=0.999, epsilon=1e-08, decay=0.0)
        model.compile(loss="categorical_crossentropy",
                      optimizer=optimizer,
                      metrics=["accuracy"])
        return model


def load_trace(path, seperator="\t"):
    """loads data to be used for predictions
    """
    file = open(path, 'r')
    sequence = [[], []]
    for line in file:
        try:
            pieces = line.strip("\n").split(seperator)
            if int(pieces[1]) == 0:
                break
            timestamp = float(pieces[0])
            direction = int(int(pieces[1])/abs(int(pieces[1])))
            sequence[0].append(timestamp)
            sequence[1].append(direction)
        except Exception as e:
            print(e)
            print("Error when trying to read packet sequence from %s!" % path)
            return None
    return sequence


def parse_arguments():
    parser = argparse.ArgumentParser(description='Perform a grid search using DF model.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-t', '--traces')
    parser.add_argument('-i', '--input_length')
    return parser.parse_args()


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
                y_count[trace_class] = 1 + y_count.get(trace_class, 0)

                # build direction sequence
                sequence = []
                with open(os.path.join(root, fname), 'r') as fi:
                    for line in fi:
                        split = line.split(delimiter)
                        direction = int(split[1])
                        if direction == 0:
                            break
                        sequence.append(direction)

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


def main():

    args = parse_arguments()

    # load data
    X, Y = load_data(args.traces)

    # initialize the optimizer and model
    model = KerasClassifier(build_fn=ConvNet.build,
                            verbose=1)
    param_grid = {
        "classes": [args.classes],
        "input_shape": [(args.input_size, 1)],
        "epochs": [20, 30, 40],
        "batch_size": [32, 64, 128],
        "filter_num": [('None', 16, 32),
                       ('None', 32, 64),
                       ('None', 64, 128),
                       ('None', 16, 32, 64, 128),
                       ('None', 32, 64, 128, 256),
                       ('None', 64, 128, 256, 512),
                       ('None', 16, 32, 64, 128, 256, 512),
                       ('None', 32, 64, 128, 256, 512, 1024),
                       ('None', 64, 128, 256, 512, 1024, 2048)],
        "fc_layer_size": [('None', 256),
                          ('None', 512),
                          ('None', 1024),
                          ('None', 256, 256),
                          ('None', 512, 512),
                          ('None', 1024, 1024),
                          ('None', 256, 256, 256),
                          ('None', 512, 512, 512),
                          ('None', 1024, 1024, 1024)]
    }
    grid = GridSearchCV(estimator=model,
                        param_grid=param_grid,
                        n_jobs=-1)
    grid_result = grid.fit(X, Y)

    # summarize results
    print("Best: %f using %s" % (grid_result.best_score_, grid_result.best_params_))
    means = grid_result.cv_results_['mean_test_score']
    stdvs = grid_result.cv_results_['std_test_score']
    parms = grid_result.cv_results_['params']
    for mean, stdev, param in zip(means, stdvs, parms):
        print("%f (%f) with: %r" % (mean, stdev, param))


if __name__ == "__main__":
    # execute only if run as a script
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
