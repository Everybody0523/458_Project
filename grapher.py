import numpy as np
import matplotlib.pyplot as plt

def graph_CDF(data_sets, data_labels, title, xlabel, ylabel):
    fig, ax = plt.subplots(figsize=(8, 4))
    for i in range(len(data_sets)):
        n, bins, patches = ax.hist(data_sets[i], 100, cumulative=True, density=True, histtype="step", label=data_labels[i])

    ax.grid(True)
    ax.legend(loc='right')
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    plt.show()

def graph_CDF_alt(data_sets, data_labels, title, xlabel, ylabel):
    fig, ax = plt.subplots(figsize=(8, 4))
    for i in range(len(data_sets)):
        total_sum = np.sum(data_sets[i])

        bucket_values = np.sort(np.array(data_sets[i], dtype=np.float32))
        probabilities = np.full(len(data_sets[i]), 1, dtype=np.float32) / len(data_sets[i])
        cumulative = np.cumsum(probabilities)

        ax.plot(bucket_values, np.cumsum(probabilities), label=data_labels[i])

    ax.grid(True)
    ax.legend(loc='right')
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    plt.show()
