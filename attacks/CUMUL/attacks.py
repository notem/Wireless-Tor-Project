# This script adapts the APIs of the different attacks to
# a unique one.
import numpy as np
from sklearn.svm import SVC
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.model_selection import GridSearchCV
from sklearn import preprocessing


class Attack(object):
    """Common interface for all the attacks.
    """

    def evaluate_attack(self, train_fv, train_labels, test_fv, test_labels):
        """Returns a dictionary containing the attack's results
        (e.g., error, TP/FP (if world=='open')).
        """
        res = {}
        pred = self.classify(train_fv, train_labels, test_fv, test_labels)

        # Accuracy.
        n_test = len(test_fv)
        acc = 0.0
        for p, t in zip(pred, test_labels):
            if p == t:
                acc += 1
        acc /= n_test
        res['error'] = 1 - acc
        # Need to have them as list of int
        res['true_labels'] = [int(x) for x in test_labels]
        res['predicted_labels'] = [int(x) for x in pred]

        return res

    def extract_features(self, packet_seq, labels=None):
        """Accepts a list of packet_sequences, returns
        a list of feature vectors.

        The input argument `labels' is required for compatibility
        with Dyer's code.
        """
        pass

    def classify(self, train_fv, train_labels, test_fv, test_labels):
        """Returns a list of label predictions for test_fv,
        training the classifier on (train_fv, train_labels).
        """
        pass


class CUMULAttack(Attack):

    def classify(self, train_fv, train_labels, test_fv, test_labels, seed=0,
                 nfolds=5):
        """Returns the accuracy of the attack trained on trainining
        feature vectors train_fv, and performed on test_fv.
        Following Panchenko's et al., the code first determines the
        best parameters (C, gamma) using grid search (using the same
        grid as the paper).
        It then uses SVM to make predictions.
        """
        print('Scaling features')
        train_fv = preprocessing.scale(train_fv)
        test_fv = preprocessing.scale(test_fv)

        print('Looking for the best parameters using {}-folds CV'.format(nfolds))
        # NOTE: these are the parameters that worked best on the
        # WCN+ dataset among those I tried
        C_range = np.logspace(11, 17, 5, base=2.0)
        gamma_range = np.logspace(-3, 3, 2, base=2.0)
        param_grid = dict(gamma=gamma_range, C=C_range)
        cv = StratifiedShuffleSplit(n_splits=nfolds, test_size=0.2,
                                    random_state=seed)
        grid = GridSearchCV(SVC(), param_grid=param_grid, cv=cv)
        grid.fit(train_fv, train_labels)

        print('Best parameters using grid search: {}'.format(grid.best_params_))
        C = grid.best_params_['C']
        gamma = grid.best_params_['gamma']

        print('Fitting SVM')
        svm = SVC(C=C, gamma=gamma, verbose=True)
        svm.fit(train_fv, train_labels)

        print('Predicting')
        pred = svm.predict(test_fv)
        e = sum(pred != np.array(test_labels)) / float(len(test_labels))
        print('Accuracy: {}'.format(1-e))
        print('Error: {}'.format(e))

        return pred

    def extract_features(self, packet_seqs, labels=None, n=100):
        """Extract feature vectors from packet sequences.
        n is the number of points to interpolate.
        """
        feature_vecs = [self._extract_features(p, n) for p in packet_seqs]

        return feature_vecs

    def _extract_features(self, packet_seq, n):
        """Extracts a feature vector from a packet sequence.
        n is the number of points to interpolate.
        """
        fv = []

        # Basic features
        in_size = 0
        out_size = 0
        in_count = 0
        out_count = 0

        # Init cumulative features
        size = packet_seq[1][0]
        c = [size]
        a = [abs(size)]

        if len(packet_seq[1]) > 1:
            for size in packet_seq[1][1:]:
                if size > 0:
                    in_size += size
                    in_count += 1
                elif size < 0:
                    out_size += abs(size)
                    out_count += 1
                else:
                    # Skip if size 0
                    continue

                c.append(c[-1] + size)
                a.append(a[-1] + abs(size))

        # Interpolate cumulative features
        cumul = np.interp(np.linspace(a[0], a[-1], n), a, c)

        fv = [in_size, out_size, in_count, out_count] + list(cumul)

        return fv


# All attacks.
ATTACKS = {
    'CUMUL': CUMULAttack,
}
