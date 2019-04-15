import random
import sys
import argparse
import os
import numpy as np

from data_utils import load_data

from keras.models import Sequential
from keras.layers import Conv1D, MaxPooling1D, BatchNormalization
from keras.layers.core import Activation, Flatten, Dense, Dropout
from keras.initializers import glorot_uniform
from keras.optimizers import Adamax
from keras.wrappers.scikit_learn import KerasClassifier
from keras.utils import np_utils
from keras.callbacks import ModelCheckpoint, EarlyStopping
from keras import backend as K
from sklearn.model_selection import GridSearchCV

random.seed(0)


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

        # avoid memory exhaustion
        K.clear_session()

        # Sequential Keras model template
        model = Sequential()

        # add convolutional layer blocks
        for block_no in range(0, len(filter_num)):
            if block_no == 0:
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
        print(model.summary())
        return model


def parse_arguments():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser(description='Perform a grid search using DF model.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-t', '--traces', type=str)
    parser.add_argument('-i', '--input_length', type=int)
    parser.add_argument('-o', '--output', type=str)
    return parser.parse_args()


#def perform_gridsearch(classes, X, Y, param_grid={}, callbacks=[]):
#
#    cut = int(X.shape[0]*0.8)
#    X_train, y_train, X_valid, y_valid = X[:cut], Y[:cut], X[cut:], Y[cut:]
#    for input_shape in param_grid['input_shape']:
#        for batch_size in param_grid['batch_size']:
#            for filter_num in param_grid['filter_num']:
#                for fc_layer_size in param_grid['fc_layer_size']:
#                
#                    print("[GridSearch] {},{},{},{}...".format(input_shape, batch_size, filter_num, fc_layer_size))
#                    model = ConvNet.build(classes,
#                                          input_shape,
#                                          filter_num=filter_num,
#                                          fc_layer_size=fc_layer_size)
#
#                    history = model.fit(X_train, y_train,
#                                       batch_size=batch_size,
#                                       epochs=300,
#                                       verbose=2,
#                                       validation_data=(X_valid, y_valid),
#                                       callbacks=callbacks)
#                    top_score = max(history['val_acc'])
#                    epoch_num = history['val_acc'].index(top_score)
#                    print("[GridSearch] ({},{}) {},{},{},{}...".format(top_score, epoch_num, input_shape, batch_size, filter_num, fc_layer_size))
#    return

def main():
    """
    Run GridSearch on DF Keras model
    """
    args = parse_arguments()

    # prepare dataset
    print("Loading data...")
    X, Y = load_data(args.traces)
    # number of sites
    classes = len(np.unique(Y))
	# convert array types to floats
    X = X.astype('float32')
    Y = Y.astype('float32')
	# convert labels to categorical
    Y = np_utils.to_categorical(Y, classes)
    K.set_image_dim_ordering("tf")  # tf is tensorflow

    # checkpoint best results
    filepath = args.output
    checkpoint = ModelCheckpoint(filepath, monitor='val_acc', save_best_only=True, mode='max')
    early_stopping = EarlyStopping(monitor='val_loss', patience=10, mode='auto', restore_best_weights=True)
    callbacks_list = [checkpoint, early_stopping]

    # initialize the optimizer and model
    model = KerasClassifier(build_fn=ConvNet.build, verbose=2, epochs=300, validation_split=0.1)
    param_grid = {
        "classes": [classes],
        "input_shape": [(args.input_length, 1)],
        "batch_size": [32, 64, 128],
        # number of items in filter tuple determines Conv. block count
        # eg. two values = two block
        "filter_num": [(16, 32),
                       (32, 64),
                       (64, 128),
                       (16, 32, 64, 128),
                       (32, 64, 128, 256),
                       (64, 128, 256, 512),
                       (16, 32, 64, 128, 256, 512),
                       (32, 64, 128, 256, 512, 1024),
                       (64, 128, 256, 512, 1024, 2048)
                      ],
        # number of items in layer size tuple determines FC layer counter
        # eg. one value == one FC layer (not including softmax)
        "fc_layer_size": [[256],
                          [512],
                          [1024],
                          (512, 512),
                          (256, 256),
                          (1024, 1024),
                          (256, 256, 256),
                          (512, 512, 512),
                          (1024, 1024, 1024)
                          ],
        "activation_function": ["relu"]
    }

    #print("Beginning Grid Search...")
    #perform_gridsearch(classes, X, Y, param_grid, callbacks_list)

    print("Parameter search space: {}".format(param_grid))
    grid = GridSearchCV(estimator=model,
                        param_grid=param_grid,
                        n_jobs=1, verbose=10)
    print("Beginning Grid Search...")
    grid_result = grid.fit(X, Y, callbacks=callbacks_list)

    ## summarize results
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
