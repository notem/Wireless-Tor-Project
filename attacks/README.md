
## PURPOSE

This directory contains scripts which perform the website fingerprinting attacks (and tuning) seen in our analysis.
The attack scripts contained in this directory are derived from the source-code provided by the attacks' original authors

This project examined three atacks: `DF`, `CUMUL`, and `k-FP`

## USAGE
#### DF [3]

In our analysis of the DF attack, we first performed hyperparameter tuning using a grid search.

In order to perform hyperparameter tuning, edit the `param_grid` variable in `tuning.py`, then run the script.
The `tuning.py` requires three arguments: `--traces`, `--input_length`, and `output`
* ex. `python3 DF/tuning.py --traces ~/traces --input_length 10000 --output ~/best.h5`

After performing hyperparameter tuning, the `attack.py` can be used to perform the true evaluation. 
Edit the `params` variable to include the results of tuning and execute the script on your dataset.
* ex. `python3 DF/attack.py --traces ~/traces --output ~/model.h5`

The `attack.py` script can be configured to save a confusion matrix file by adding the command line argument `--confusion_matrix cm.txt`.
We provide a script to display the confusion matrix in the `graphing` directory.

#### k-FP [2] & CUMUL [1]

During our analysis, we also examined the k-FP and CUMUL attacks in order to investigate the performance of machine-learning attacks using handcrafted features.
For each of these attacks, the plaintext dataset must be further processed in feature files.

A feature dictionary can be computed for k-FP by using the following command:
* ex. `python3 k-FP/k-FP.py --dictionary --features ./features.dct --traces /path/to/traces`

A directory of feature files can be generated for the CUMUL command by using this command:
* ex. `python3 CUMUL/extract_features --out ./cumul_features --traces /path/to/traces`

After the dataset has properly been processed into feature files, the k-FP and CUMUL classification algorithms can be used.
The k-FP script will load features dictionary, train a random forest classifier, and print results to standard output (ie. the terminal window).
The CUMUL attack script will load the previously generated feature files, divide the files into train/test/validate sets, and save the results of to a json file.

To perform the k-FP attack, use this command:
* ex. `python3 k-FP/k-FP.py --evaluate --features ./features.dct`

And use this command to perform the CUMUL attack:
* ex. `python3 CUMUL/classify.py --features ./cumul_features --train 0.8 --test 0.1 --out ./cumul_results.json`


## References
[1] Panchenko et al.  “Website fingerprinting at internet scale,” NDSS 2016.

[2] Hayes et al. “k-fingerprinting: A robust scalable website  fingerprinting  technique,” in USENIX 2016.

[3] Sirinam et al. “Deep fingerprinting: Undermining website fingerprinting defenses with deep  learning,” CCS 2018.
