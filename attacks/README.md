
## PURPOSE

This directory contains scripts which perform the website fingerprinting attacks (and tuning) seen in our analysis.

This project examined three atacks: DF, CUMUL, and k-FP

## USAGE
#### DF

In order to perform hyperparameter tuning, edit the `param_grid` variable in `tuning.py`, then run the script.
The `tuning.py` requires three arguments: `--traces`, `--input_length`, and `output`
* ex. `python3 DF/tuning.py --traces ~/traces --input_length 10000 --output ~/best.h5`

After performing hyperparameter tuning, the `attack.py` can be used to perform the true evaluation. 
Edit the `params` variable to include the results of tuning and execute the script on your dataset.
* ex. `python3 DF/attack.py --traces ~/traces --output ~/model.h5`

#### CUMUL




#### k-FP

