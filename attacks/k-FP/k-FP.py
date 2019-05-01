import RF_fextract
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
#import matplotlib.pyplot as plt
import pickle
import sys
import os

#### Parameters ####
num_Trees = 1000


############ Feeder functions ############
def checkequal(lst):
    return lst[1:] == lst[:-1]


############ Non-Feeder functions ########
def generate_features(traces_root_path, feature_path, use_time_features=True):
    """
    :param traces_root_path:
    :param feature_path:
    :return:
    """
    print("Generating features from traces.")
    feature_labels = []
    data_dict = dict()

    features_l = []
    labels = []
    i = 0
    for root, dirs, files in os.walk(traces_root_path):
        for file in files:
            try:
                trace_class = int(file.split("_")[0])
                trace_instance = int(file.split("_")[1])

                try:
                    tcp_dump = open(os.path.join(root, file)).readlines()
                    features, feature_labels = RF_fextract.TOTAL_FEATURES(tcp_dump, use_time_features=use_time_features)

                    features_l.append([features])
                    labels.append((trace_class, trace_instance))

                    i += 1
                    if i % 500 == 0: print(i)
                except Exception as e:
                    print(e)
                    pass
            except Exception as e:
                pass

    size = len(features_l)
    assert size > 0
    print('Count of instances: {}'.format(size))

    train_cut = int(size*0.8)
    data_dict['train_features'] = features_l[:train_cut]
    data_dict['train_labels'] = labels[:train_cut]

    test_cut = train_cut + int(size*0.1)
    data_dict['test_features'] = features_l[train_cut:test_cut]
    data_dict['test_labels'] = labels[train_cut:test_cut]

    data_dict['validate_features'] = features_l[test_cut:]
    data_dict['validate_labels'] = labels[test_cut:]

    data_dict['feature_labels'] = [feature_labels]

    print("Saving features to pickle file.")
    fileObject = open(feature_path, 'wb')
    pickle.dump(data_dict, fileObject)
    fileObject.close()


def load_features(path_to_features):
    """Prepare monitored data in to training and test sets."""

    file_obj = open(path_to_features, 'rb')
    dic = pickle.load(file_obj)

    feature_labels = dic['feature_labels']

    # load test data and labels
    test_data = dic['test_features']
    test_label = dic['test_labels']

    # combine the validation data and train data to
    # act as the full training data set
    train_data = dic['validate_features']
    train_data.extend(dic['train_features'])
    train_label = dic['validate_labels']
    train_label.extend(dic['train_labels'])

    flat_train_data = []
    flat_test_data = []
    for tr in train_data:
        flat_train_data.append(list(sum(tr, ())))
    for te in test_data:
        flat_test_data.append(list(sum(te, ())))
    training_features = zip(flat_train_data, train_label)
    test_features = zip(flat_test_data, test_label)

    return training_features, test_features, feature_labels


def RF_closedworld(path_to_dict):
    """Closed world RF classification of data -- only uses sk.learn classification - does not do additional k-nn."""

    training, test, feature_labels = load_features(path_to_dict)
    tr_data, tr_label1 = zip(*training)
    tr_label = [list(t) for t in zip(*tr_label1)][0]
    te_data, te_label1 = zip(*test)
    te_label = [list(t) for t in zip(*te_label1)][0]

    print("Training ...")
    model = RandomForestClassifier(n_jobs=2, n_estimators=num_Trees, oob_score=True)
    model.fit(tr_data, tr_label)
    print("RF accuracy = ", model.score(te_data, te_label))

    print("Feature importance scores:")
    importance = zip(model.feature_importances_, feature_labels[0])
    sorted_importance = sorted(importance, key=lambda tup: tup[0], reverse=True)
    index = 0
    for score, label in sorted_importance:
        index += 1
        print("%d. %s (%f)" % (index, label, score))

    scores = cross_val_score(model, np.array(tr_data), np.array(tr_label))
    print("cross_val_score = ", scores.mean())
    print("OOB score = ", model.oob_score_)


def parse_arguments():
    """
    :return:
    """
    import argparse
    parser = argparse.ArgumentParser(description='k-FP benchmarks')
    parser.add_argument('--dictionary',
                        action='store_true',
                        help='Build feature dictionary.')
    parser.add_argument('--evaluate',
                        action='store_true',
                        help='Closed world classification.')
    parser.add_argument('--features',
                        nargs=1,
                        type=str,
                        help="Path to feature dictionary.")
    parser.add_argument('--traces',
                        nargs=1,
                        type=str,
                        help="Path to traces root directory.")
    return parser.parse_args()


def main():
    """
    :return:
    """
    args = parse_arguments()

    if args.dictionary:

        # Example command line:
        # $ python k-FP.py --dictionary --features /path/to/features --traces /path/to/traces
        generate_features(args.traces[0], args.features[0], use_time_features=args.time)

    elif args.evaluate:

        # Example command line:
        # $ python k-FP.py --evaluate --features /path/to/features
        RF_closedworld(args.features[0])

    return 0


if __name__ == "__main__":
    # execute only if run as a script
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
