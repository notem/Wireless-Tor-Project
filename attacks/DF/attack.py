import keras
from keras import backend as K
from keras.models import Sequential, load_model
from keras.layers import Conv1D, MaxPooling1D, AveragePooling1D, BatchNormalization
from keras.layers.core import Activation, Flatten, Dense, Dropout
from keras.layers.advanced_activations import ELU
from keras.initializers import glorot_uniform
from keras.callbacks import ModelCheckpoint, EarlyStopping
import random
from keras.utils import np_utils
from keras.optimizers import Adam, SGD, Nadam, Adamax
import numpy as np
import time
import sys
import os
from timeit import default_timer as timer
from pprint import pprint
import argparse

random.seed(0)

# tuned model parameters
# !CHANGEME
params = { 
          "batchsize": 32,
          "activation_function": "relu",
          "input_shape": (9000, 1),
          "filter_num": (32, 64, 128, 256),
          "fc_layer_size": (1024, 1024)
         }

# define the ConvNet
class ConvNet:
    @staticmethod
    def build(classes,
              input_shape,
              activation_function="relu",
              filter_num=(32, 64, 128, 256),
              kernel_size=8,
              conv_stride_size=1,
              pool_stride_size=4,
              pool_size=8,
              fc_layer_size=(512, 512)):

        # Sequential Keras model template
        model = Sequential()

        # add convolutional layer blocks
        for block_no in range(0, len(filter_num)):
            if block_no == 0:
                print(filter_num[block_no])
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
                                   name='block{}_pool'.format(block_no)))

            model.add(Dropout(0.1, name='block{}_dropout'.format(block_no)))

        # flatten output before fc layers
        model.add(Flatten(name='flatten'))

        # add fully-connected layers
        for layer_no in range(0, len(fc_layer_size)):
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

def LoadDataMonTiming(length, directory):
    """
    Prepare the training, testing, and validation datasets
    """
    def load_from_dir(dirpath, delimiter=' ', max_instances_per_class=0):
        """
        Read-in trace files from a directory.
        """
        X = []
        y = []
        y_count = dict()
        l = []
        for root, dirs, files in os.walk(dirpath):
            for fname in files:

                # trace_class is derived from file name (eg. 'C-n' where C is class and n is instance)
                trace_class = int(fname.split('_')[0])
                y_count[trace_class] = 1 + y_count.get(trace_class, 0)

                # build direction sequence
                sequence = []
                with open(os.path.join(root, fname), 'r') as fi:
                    for line in fi:
                        split = line.split(delimiter)
                        if len(split) > 1:
                            direction = int(split[1])
                        else:
                            direction = int(line.split("\t")[1])
                        if direction == 0:
                            break
                        if abs(direction) > 512:
                            direction /= abs(direction)
                            sequence.append(direction)

                l.append(len(sequence))
                # add sequence and label
                sequence = np.array(sequence)
                sequence.resize((length, 1))
                X.append(sequence)
                y.append(trace_class)

        return np.array(X), np.array(y), sum(l)/len(l)

    X, Y, avg_len = load_from_dir(directory)
    print(avg_len)

    # shuffle
    s = np.arange(Y.shape[0])
    np.random.seed(0)
    np.random.shuffle(s)
    X, Y = X[s], Y[s]

    cut = int(len(Y) * 0.8)
    cut2 = int(len(Y) * 0.9)
    X_train, y_train = X[:cut], Y[:cut]
    X_valid, y_valid = X[cut:cut2], Y[cut:cut2]
    X_test, y_test = X[cut2:], Y[cut2:]
    return X_train, y_train, X_valid, y_valid, X_test, y_test


def parse_arguments():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(description='Train and test the DeepFingerprinting model.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-t', '--traces',
                        type=str,
                        default='traces',
                        metavar='<trace_data>',
                        help='Path to the directory where the training data is stored.')
    parser.add_argument('-o', '--output',
                        type=str,
                        default='models/DF.h5',
                        metavar='<output>',
                        help='Location to store the file.')
    parser.add_argument('-q', '--quiet',
                        action="store_true",
                        help="Lower verbosity of output.")
    return parser.parse_args()


def main():
    """
    """

    # # # # # # # # 
    # Parse arguments
    # # # # # # # # 
    args = parse_arguments()

    VERBOSE = 1 if not args.quiet else 2

    # # # # # # # # 
    # Load the dataset
    # # # # # # # # 
    print("Loading dataset...")
    load_start = timer()
    X_train, y_train, X_valid, y_valid, X_test, y_test = \
        LoadDataMonTiming(params["input_shape"][0], args.traces)
    K.set_image_dim_ordering("tf")  # tf is tensorflow

    # consider them as float and normalize
    X_train = X_train.astype('float32')
    X_valid = X_valid.astype('float32')
    X_test = X_test.astype('float32')
    y_train = y_train.astype('float32')
    y_valid = y_valid.astype('float32')
    y_test = y_test.astype('float32')

    NB_CLASSES = len(set(list(y_train)))

    # convert class vectors to binary class matrices
    y_train = np_utils.to_categorical(y_train, NB_CLASSES)
    y_valid = np_utils.to_categorical(y_valid, NB_CLASSES)
    y_test = np_utils.to_categorical(y_test, NB_CLASSES)
    load_end = timer()

    print("Shape:", X_train.shape)
    print(X_train.shape[0], 'train samples')
    print(X_valid.shape[0], 'validation samples')
    print(X_test.shape[0], 'test samples')

    # # # # # # # # 
    # Build and compile model
    # # # # # # # # 
    create_start = timer()
    print("Compiling model...")
    model = ConvNet.build(classes=NB_CLASSES, 
                          input_shape=params["input_shape"],
                          filter_num=params["filter_num"],
                          fc_layer_size=params["fc_layer_size"],
                          activation_function=params["activation_function"])
    print(model.summary())
    create_end = timer()

    # # # # # # # # 
    # Train the model
    # # # # # # # # 
    filepath = args.output
    checkpoint = ModelCheckpoint(filepath, monitor='val_acc', save_best_only=True, mode='max')
    early_stopping = EarlyStopping(monitor='val_loss', patience=10, mode='auto', restore_best_weights=True)
    callbacks_list = [checkpoint, early_stopping]

    train_start = timer()
    history = model.fit(X_train, y_train,
                        batch_size=params["batchsize"],
                        epochs=300,
                        verbose=VERBOSE,
                        validation_data=(X_valid, y_valid),
                        callbacks=callbacks_list)
    train_end = timer()

    # Save & reload model
    model.save(filepath)
    del model
    model = load_model(filepath)

    # # # # # # # # 
    # Test the model
    # # # # # # # # 
    test_start = timer()
    score = model.evaluate(X_test, y_test,
                           verbose=VERBOSE)
    test_end = timer()
    score_train = model.evaluate(X_train, y_train,
                                 verbose=VERBOSE)

    # # # # # # # # 
    # Print results
    # # # # # # # # 
    print("\n=> Train score:", score_train[0])
    print("=> Train accuracy:", score_train[1])

    print("\n=> Test score:", score[0])
    print("=> Test accuracy:", score[1])

    print("\n=> Loading Data Done! : %.2f s" % (load_end - load_start))
    print("=> Creating Conv Model Done! : %.2f s" % (create_end - create_start))
    print("=> Training and Validating Done! : %.2f s" % (train_end - train_start))
    print("=> Testing Done! : %.2f s" % (test_end - test_start))

    print("<==H=I=S=T=O=R=Y==>")
    pprint(history.history)
    print("<=================>")

    # summarize history for accuracy
    sys.stdout.close()


if __name__ == "__main__":
    # execute only if run as a script
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
