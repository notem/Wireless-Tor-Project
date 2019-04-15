"""
@file: plot.py
@author: Riley Lloyd <rvl6148@rit.edu>
@description: This file takes deep learning epoch data in JSON format
and plots it on a graph that is saved to the current directory.
"""

import sys
import json
import matplotlib.pyplot as plt


def main():
    # Set local variables for easy editing
    input_file = "in-file-name.json"
    output_file = "figure-file-name.png"

    # Open file and load JSON data
    with open(input_file) as f:
        data = json.load(f)

    # Ensure data lengths are the same to prevent errors
    if len(data["acc"]) is not len(data["val_acc"]):
        print("Error: The accuracy values are different in size. This will cause issues.")
        sys.exit()
    else:
        t = range(len(data["acc"]))

    # Initialize figure and ax1
    fig, ax1 = plt.subplots()

    # Label and populate the axes and ax1
    color = 'tab:red'
    ax1.set_xlabel('Epoch')
    ax1.set_ylabel('Accuracy (%)', color=color)
    ax1.plot(t, data["acc"], color=color, label='Training')
    ax1.tick_params(axis='y', labelcolor=color)

    # Add addition plot of the val accuracy
    ax1.plot(t, data["val_acc"], color=color, linestyle=':', label='Validation')

    # instantiate a second axes that shares the same x-axis
    ax2 = ax1.twinx()
    color = 'tab:blue'
    ax2.set_ylabel('Loss Score', color=color)
    ax2.plot(t, data["loss"], color=color)
    ax2.tick_params(axis='y', labelcolor=color)

    # Add addition plot of the val loss
    ax2.plot(t, data["val_loss"], color=color, linestyle=':')

    # Tidy up and print legend
    fig.tight_layout()
    ax1.legend()

    # Uncomment the below to show the plot
    # plt.show()
    plt.savefig(output_file)

    plt.close(fig)


if __name__ == "__main__":
    main()
