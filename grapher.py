import numpy as np
import matplotlib.pyplot as plt

def graph_CDF(data_sets, data_labels, title, xlabel, ylabel, use_log_scale=False):
    fig, ax = plt.subplots(figsize=(8, 4))
    for i in range(len(data_sets)):
        n, bins, patches = ax.hist(data_sets[i], 100, cumulative=True, density=True, histtype="step", label=data_labels[i])
    
    if (use_log_scale):
        plt.xscale('log')
    ax.grid(True)
    ax.legend(loc='right')
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    plt.show()

def graph_CDF_alt(data_sets, data_labels, title, xlabel, ylabel, lineLen=None, use_log_scale=False):
    fig, ax = plt.subplots(figsize=(8, 4))
    for i in range(len(data_sets)):
        total_sum = np.sum(data_sets[i])

        bucket_values = np.sort(np.array(data_sets[i], dtype=np.float32))
        probabilities = np.full(len(data_sets[i]), 1, dtype=np.float32) / len(data_sets[i])
        cumulative = np.cumsum(probabilities)

        ax.plot(bucket_values, np.cumsum(probabilities), label=data_labels[i], linewidth=lineLen)

    if use_log_scale:
        plt.xscale('log')
    ax.grid(True)
    ax.legend(loc='right')
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    plt.show()


def graph_RTTs(EST_arr, OBS_arr, attribute="", num=0):
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot([i for i in range(len(OBS_arr))], OBS_arr, label='Observed RTT')
    ax.plot([i for i in range(len(EST_arr))], EST_arr, label='Estimated RTT', linewidth=1.75)
    ax.grid(True)
    ax.legend(loc='right')
    ax.set_title('RTT ' + " " + attribute + " " + str(num))
    ax.set_xlabel('Time')
    ax.set_ylabel('RTT (ms)')
    plt.show()

def graph_RTT_over_time(times1, rtts1, times2, rtts2, times3, rtts3):
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(times1, rtts1)
    ax.plot(times2, rtts2)
    ax.plot(times2, rtts2)
    ax.grid(True)
    ax.legend(loc='right')
    ax.set_title('Estimated RTT over time')
    ax.set_xlabel('Time')
    ax.set_ylabel('RTT (ms)')
    plt.show()

def graph_RTT_over_time(times, rtts):
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.scatter(times, rtts)
    ax.grid(True)
    ax.legend(loc='right')
    ax.set_title('Estimated RTT over time')
    ax.set_xlabel('Time')
    ax.set_ylabel('RTT (ms)')
    plt.show()
